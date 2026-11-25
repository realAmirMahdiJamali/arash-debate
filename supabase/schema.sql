create extension if not exists pgcrypto;

create table if not exists public.user_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  student_id text unique not null,
  role text not null check (role in ('admin','judge','observer')),
  observer_group smallint check (observer_group between 1 and 4),
  force_password_change boolean not null default false,
  created_at timestamptz not null default now(),
  constraint observer_group_role_check check ((role = 'observer' and observer_group is not null) or (role <> 'observer' and observer_group is null))
);

create table if not exists public.sessions (
  id uuid primary key default gen_random_uuid(),
  session_number integer not null unique,
  title text not null,
  topic text not null default '',
  date_fa text not null default '',
  date date,
  status text not null default 'scheduled' check (status in ('scheduled','live','completed','published')),
  poll_open boolean not null default false,
  published boolean not null default false,
  teams jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.judge_scores (
  id uuid primary key default gen_random_uuid(),
  session_id uuid not null references public.sessions(id) on delete cascade,
  judge_id uuid not null references public.user_profiles(id) on delete cascade,
  team_id uuid not null,
  argument numeric(5,2) not null check (argument between 0 and 30),
  response numeric(5,2) not null check (response between 0 and 25),
  delivery numeric(5,2) not null check (delivery between 0 and 15),
  structure numeric(5,2) not null check (structure between 0 and 10),
  teamwork numeric(5,2) not null check (teamwork between 0 and 10),
  time numeric(5,2) not null check (time between 0 and 10),
  note text not null default '',
  updated_at timestamptz not null default now(),
  unique(session_id,judge_id,team_id)
);

create table if not exists public.observer_feedback (
  id uuid primary key default gen_random_uuid(),
  session_id uuid not null references public.sessions(id) on delete cascade,
  observer_id uuid not null references public.user_profiles(id) on delete cascade,
  group_no smallint not null check (group_no between 1 and 4),
  strength text not null,
  weakness text not null,
  suggestion text not null,
  updated_at timestamptz not null default now(),
  unique(session_id,group_no)
);

create table if not exists public.published_results (
  id uuid primary key default gen_random_uuid(),
  session_id uuid not null references public.sessions(id) on delete cascade,
  team_id uuid not null,
  team_name text not null,
  argument numeric(6,3) not null,
  response numeric(6,3) not null,
  delivery numeric(6,3) not null,
  structure numeric(6,3) not null,
  teamwork numeric(6,3) not null,
  time numeric(6,3) not null,
  average numeric(7,3) not null,
  judge_count integer not null,
  rank integer not null,
  published_at timestamptz not null default now(),
  unique(session_id,team_id)
);

create table if not exists public.poll_votes (
  id uuid primary key default gen_random_uuid(),
  session_id uuid not null references public.sessions(id) on delete cascade,
  team_id uuid not null,
  voter_key uuid not null,
  created_at timestamptz not null default now(),
  unique(session_id,voter_key)
);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.user_profiles(id,student_id,role,observer_group,force_password_change)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'student_id', split_part(new.email,'@',1)),
    coalesce(new.raw_user_meta_data->>'role','judge'),
    case when coalesce(new.raw_user_meta_data->>'role','judge') = 'observer' then coalesce((new.raw_user_meta_data->>'observer_group')::smallint,1) else null end,
    coalesce((new.raw_user_meta_data->>'force_password_change')::boolean,false)
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_amj on auth.users;
create trigger on_auth_user_created_amj after insert on auth.users for each row execute procedure public.handle_new_user();

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$ select exists(select 1 from public.user_profiles where id = auth.uid() and role = 'admin'); $$;

create or replace function public.complete_password_change()
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.user_profiles set force_password_change = false where id = auth.uid();
end;
$$;

create or replace function public.get_poll_results(p_session_id uuid)
returns table(team_id uuid, count bigint)
language sql
stable
security definer
set search_path = public
as $$
  select v.team_id, count(*) from public.poll_votes v join public.sessions s on s.id = v.session_id
  where v.session_id = p_session_id group by v.team_id;
$$;

create or replace function public.finalize_session(p_session_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  s public.sessions%rowtype;
  team jsonb;
  team_uuid uuid;
  judge_total integer;
begin
  if not public.is_admin() then raise exception 'اجازه دسترسی مدیر لازم است'; end if;
  select * into s from public.sessions where id = p_session_id for update;
  if not found then raise exception 'دوره پیدا نشد'; end if;
  if jsonb_array_length(s.teams) <> 4 then raise exception 'دوره باید دقیقاً چهار تیم داشته باشد'; end if;
  for team in select value from jsonb_array_elements(s.teams) as x(value) loop
    team_uuid := (team->>'id')::uuid;
    select count(*) into judge_total from public.judge_scores where session_id=p_session_id and team_id=team_uuid;
    if judge_total <> 5 then raise exception 'برای هر تیم باید پنج فرم داوری کامل ثبت شود'; end if;
  end loop;
  delete from public.published_results where session_id=p_session_id;
  insert into public.published_results(session_id,team_id,team_name,argument,response,delivery,structure,teamwork,time,average,judge_count,rank)
  with team_rows as (
    select
      (team_json->>'id')::uuid as team_id,
      team_json->>'name' as team_name,
      avg(j.argument) as argument,
      avg(j.response) as response,
      avg(j.delivery) as delivery,
      avg(j.structure) as structure,
      avg(j.teamwork) as teamwork,
      avg(j.time) as time,
      avg(j.argument+j.response+j.delivery+j.structure+j.teamwork+j.time) as average,
      count(j.id)::integer as judge_count
    from jsonb_array_elements(s.teams) as x(team_json)
    left join public.judge_scores j on j.session_id=p_session_id and j.team_id=(team_json->>'id')::uuid
    group by team_json
  ), ranked as (
    select *, row_number() over(order by average desc, argument desc, response desc) as rank from team_rows
  ) select p_session_id,team_id,team_name,argument,response,delivery,structure,teamwork,time,average,judge_count,rank from ranked;
  update public.sessions set published=true,status='published',updated_at=now() where id=p_session_id;
end;
$$;

alter table public.user_profiles enable row level security;
alter table public.sessions enable row level security;
alter table public.judge_scores enable row level security;
alter table public.observer_feedback enable row level security;
alter table public.published_results enable row level security;
alter table public.poll_votes enable row level security;

drop policy if exists profiles_read_self_or_admin on public.user_profiles;
create policy profiles_read_self_or_admin on public.user_profiles for select to authenticated using (id=auth.uid() or public.is_admin());
drop policy if exists sessions_public_read on public.sessions;
create policy sessions_public_read on public.sessions for select to anon,authenticated using (true);
drop policy if exists sessions_admin_write on public.sessions;
create policy sessions_admin_write on public.sessions for all to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists scores_judge_read on public.judge_scores;
create policy scores_judge_read on public.judge_scores for select to authenticated using (public.is_admin() or exists(select 1 from public.user_profiles p where p.id=auth.uid() and p.role in ('judge','admin')));
drop policy if exists scores_judge_insert on public.judge_scores;
create policy scores_judge_insert on public.judge_scores for insert to authenticated with check (judge_id=auth.uid() and exists(select 1 from public.user_profiles p where p.id=auth.uid() and p.role in ('judge','admin')));
drop policy if exists scores_judge_update on public.judge_scores;
create policy scores_judge_update on public.judge_scores for update to authenticated using (judge_id=auth.uid() or public.is_admin()) with check (judge_id=auth.uid() or public.is_admin());
drop policy if exists feedback_read on public.observer_feedback;
create policy feedback_read on public.observer_feedback for select to anon,authenticated using (true);
drop policy if exists feedback_insert on public.observer_feedback;
create policy feedback_insert on public.observer_feedback for insert to authenticated with check (observer_id=auth.uid() and exists(select 1 from public.user_profiles p where p.id=auth.uid() and p.role='observer' and p.observer_group=group_no));
drop policy if exists feedback_update on public.observer_feedback;
create policy feedback_update on public.observer_feedback for update to authenticated using (observer_id=auth.uid() or public.is_admin()) with check (observer_id=auth.uid() or public.is_admin());
drop policy if exists published_results_public_read on public.published_results;
create policy published_results_public_read on public.published_results for select to anon,authenticated using (true);
drop policy if exists poll_votes_insert on public.poll_votes;
create policy poll_votes_insert on public.poll_votes for insert to anon,authenticated with check (
  exists(select 1 from public.sessions s where s.id=session_id and s.poll_open=true and exists(select 1 from jsonb_array_elements(s.teams) as x(team_json) where (team_json->>'id')::uuid=team_id))
);
drop policy if exists poll_votes_admin_read on public.poll_votes;
create policy poll_votes_admin_read on public.poll_votes for select to authenticated using (public.is_admin());
drop policy if exists poll_votes_realtime_read on public.poll_votes;
create policy poll_votes_realtime_read on public.poll_votes for select to anon,authenticated using (true);

grant select on public.sessions,public.published_results to anon,authenticated;
grant insert,update,delete on public.sessions to authenticated;
grant select on public.user_profiles to authenticated;
grant select,insert,update on public.judge_scores to authenticated;
grant select,insert,update on public.observer_feedback to authenticated;
grant insert on public.poll_votes to anon,authenticated;
grant select on public.poll_votes to anon,authenticated;
grant execute on function public.get_poll_results(uuid) to anon,authenticated;
grant execute on function public.complete_password_change() to authenticated;
grant execute on function public.finalize_session(uuid) to authenticated;

insert into public.sessions(session_number,title,topic,date_fa,date,status,teams)
values (1,'نخستین دوره مناظره کلاسی','موضوع مناظره پس از ثبت توسط مدیر نمایش داده می‌شود.','۴ آذر ۱۴۰۵','2026-11-25','scheduled',
jsonb_build_array(
 jsonb_build_object('id','10000000-0000-4000-8000-000000000001','name','تیم اول · موافق'),
 jsonb_build_object('id','10000000-0000-4000-8000-000000000002','name','تیم دوم · مخالف'),
 jsonb_build_object('id','10000000-0000-4000-8000-000000000003','name','تیم سوم · موافق دوم'),
 jsonb_build_object('id','10000000-0000-4000-8000-000000000004','name','تیم چهارم · مخالف دوم')
)) on conflict(session_number) do nothing;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_publication_tables WHERE pubname='supabase_realtime' AND schemaname='public' AND tablename='sessions') THEN ALTER PUBLICATION supabase_realtime ADD TABLE public.sessions; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_publication_tables WHERE pubname='supabase_realtime' AND schemaname='public' AND tablename='judge_scores') THEN ALTER PUBLICATION supabase_realtime ADD TABLE public.judge_scores; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_publication_tables WHERE pubname='supabase_realtime' AND schemaname='public' AND tablename='observer_feedback') THEN ALTER PUBLICATION supabase_realtime ADD TABLE public.observer_feedback; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_publication_tables WHERE pubname='supabase_realtime' AND schemaname='public' AND tablename='published_results') THEN ALTER PUBLICATION supabase_realtime ADD TABLE public.published_results; END IF;
END $$;
grant select on public.observer_feedback to anon,authenticated;

create table if not exists public.judge_notes (
  id uuid primary key default gen_random_uuid(),
  session_id uuid not null references public.sessions(id) on delete cascade,
  judge_id uuid not null references public.user_profiles(id) on delete cascade,
  team_id uuid not null,
  criterion_key text not null check (criterion_key in ('argument','response','delivery','structure','teamwork','time')),
  note text not null default '',
  updated_at timestamptz not null default now(),
  unique(session_id,judge_id,team_id,criterion_key)
);

alter table public.judge_notes enable row level security;
drop policy if exists judge_notes_public_read on public.judge_notes;
create policy judge_notes_public_read on public.judge_notes for select to anon,authenticated using (true);
drop policy if exists judge_notes_judge_insert on public.judge_notes;
create policy judge_notes_judge_insert on public.judge_notes for insert to authenticated with check (judge_id=auth.uid() and exists(select 1 from public.user_profiles p where p.id=auth.uid() and p.role in ('judge','admin')));
drop policy if exists judge_notes_judge_update on public.judge_notes;
create policy judge_notes_judge_update on public.judge_notes for update to authenticated using (judge_id=auth.uid() or public.is_admin()) with check (judge_id=auth.uid() or public.is_admin());
grant select on public.judge_notes to anon,authenticated;
grant insert,update on public.judge_notes to authenticated;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_publication_tables WHERE pubname='supabase_realtime' AND schemaname='public' AND tablename='poll_votes') THEN ALTER PUBLICATION supabase_realtime ADD TABLE public.poll_votes; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_publication_tables WHERE pubname='supabase_realtime' AND schemaname='public' AND tablename='judge_notes') THEN ALTER PUBLICATION supabase_realtime ADD TABLE public.judge_notes; END IF;
END $$;
