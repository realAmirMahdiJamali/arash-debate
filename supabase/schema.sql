create extension if not exists pgcrypto;

create table if not exists public.app_roles (
  role_key text primary key,
  title text not null,
  system_role boolean not null default false,
  created_at timestamptz not null default now()
);
insert into public.app_roles(role_key,title,system_role) values
 ('admin','مدیر',true),('judge','داور',true),('participant','شرکت‌کننده',true),('observer','مشاهده‌گر',true)
on conflict(role_key) do update set title=excluded.title,system_role=true;

create table if not exists public.user_profiles (
 id uuid primary key references auth.users(id) on delete cascade,
 username text not null unique,
 display_name text not null default '',
 role_key text not null references public.app_roles(role_key),
 active boolean not null default true,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);
create unique index if not exists user_profiles_username_exact on public.user_profiles(username);

create table if not exists public.debate_sessions (
 id uuid primary key default gen_random_uuid(),
 title text not null,
 topic text not null default '',
 session_date date,
 status text not null default 'scheduled' check(status in ('scheduled','active','completed')),
 published boolean not null default false,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);
create table if not exists public.debate_groups (
 id uuid primary key default gen_random_uuid(),
 session_id uuid not null references public.debate_sessions(id) on delete cascade,
 name text not null,
 description text not null default '',
 created_at timestamptz not null default now()
);
create table if not exists public.debate_members (
 id uuid primary key default gen_random_uuid(),
 session_id uuid not null references public.debate_sessions(id) on delete cascade,
 group_id uuid references public.debate_groups(id) on delete set null,
 full_name text not null,
 student_code text not null default '',
 role_title text not null default '',
 created_at timestamptz not null default now()
);
create table if not exists public.team_scores (
 id uuid primary key default gen_random_uuid(),
 session_id uuid not null references public.debate_sessions(id) on delete cascade,
 group_id uuid not null references public.debate_groups(id) on delete cascade,
 judge_id uuid not null references public.user_profiles(id) on delete cascade,
 argument numeric(5,2) not null check(argument between 0 and 30),
 response numeric(5,2) not null check(response between 0 and 25),
 delivery numeric(5,2) not null check(delivery between 0 and 15),
 structure numeric(5,2) not null check(structure between 0 and 10),
 teamwork numeric(5,2) not null check(teamwork between 0 and 10),
 time_management numeric(5,2) not null check(time_management between 0 and 10),
 updated_at timestamptz not null default now(),
 unique(session_id,group_id,judge_id)
);
create table if not exists public.individual_scores (
 id uuid primary key default gen_random_uuid(),
 session_id uuid not null references public.debate_sessions(id) on delete cascade,
 member_id uuid not null references public.debate_members(id) on delete cascade,
 judge_id uuid not null references public.user_profiles(id) on delete cascade,
 score numeric(3,1) not null check(score between 0 and 10 and score*10=trunc(score*10)),
 note text not null default '',
 updated_at timestamptz not null default now(),
 unique(session_id,member_id,judge_id)
);

create or replace function public.current_role()
returns text language sql stable security definer set search_path=public
as $$ select role_key from public.user_profiles where id=auth.uid() and active=true $$;
create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path=public
as $$ select coalesce(public.current_role()='admin',false) $$;
create or replace function public.guard_admin_profile()
returns trigger language plpgsql security definer set search_path=public
as $$ begin
 if auth.uid() is not null and not public.is_admin() then raise exception 'admin only'; end if;
 if tg_op='DELETE' then
  if old.role_key='admin' then raise exception 'admin profile cannot be deleted'; end if;
  return old;
 end if;
 if tg_op='UPDATE' and old.role_key='admin' and new.role_key<>'admin' then raise exception 'admin role cannot be removed'; end if;
 return new;
end $$;
drop trigger if exists profiles_admin_guard on public.user_profiles;
create trigger profiles_admin_guard before insert or update or delete on public.user_profiles for each row execute function public.guard_admin_profile();

alter table public.app_roles enable row level security;
alter table public.user_profiles enable row level security;
alter table public.debate_sessions enable row level security;
alter table public.debate_groups enable row level security;
alter table public.debate_members enable row level security;
alter table public.team_scores enable row level security;
alter table public.individual_scores enable row level security;

drop policy if exists roles_read on public.app_roles;
create policy roles_read on public.app_roles for select to anon,authenticated using(true);
drop policy if exists roles_admin on public.app_roles;
create policy roles_admin on public.app_roles for all to authenticated using(public.is_admin()) with check(public.is_admin());
drop policy if exists profiles_self_admin on public.user_profiles;
create policy profiles_self_admin on public.user_profiles for select to authenticated using(id=auth.uid() or public.is_admin());
drop policy if exists profiles_admin_all on public.user_profiles;
create policy profiles_admin_all on public.user_profiles for all to authenticated using(public.is_admin()) with check(public.is_admin());
drop policy if exists sessions_read on public.debate_sessions;
create policy sessions_read on public.debate_sessions for select to anon,authenticated using(true);
drop policy if exists sessions_admin on public.debate_sessions;
create policy sessions_admin on public.debate_sessions for all to authenticated using(public.is_admin()) with check(public.is_admin());
drop policy if exists groups_read on public.debate_groups;
create policy groups_read on public.debate_groups for select to anon,authenticated using(true);
drop policy if exists groups_admin on public.debate_groups;
create policy groups_admin on public.debate_groups for all to authenticated using(public.is_admin()) with check(public.is_admin());
drop policy if exists members_read on public.debate_members;
create policy members_read on public.debate_members for select to anon,authenticated using(true);
drop policy if exists members_admin on public.debate_members;
create policy members_admin on public.debate_members for all to authenticated using(public.is_admin()) with check(public.is_admin());
drop policy if exists team_scores_read on public.team_scores;
create policy team_scores_read on public.team_scores for select to authenticated using(public.is_admin() or judge_id=auth.uid());
drop policy if exists team_scores_insert on public.team_scores;
create policy team_scores_insert on public.team_scores for insert to authenticated with check(judge_id=auth.uid() and public.current_role()='judge');
drop policy if exists team_scores_update on public.team_scores;
create policy team_scores_update on public.team_scores for update to authenticated using(judge_id=auth.uid() or public.is_admin()) with check(judge_id=auth.uid() or public.is_admin());
drop policy if exists individual_scores_read on public.individual_scores;
create policy individual_scores_read on public.individual_scores for select to authenticated using(public.is_admin() or judge_id=auth.uid());
drop policy if exists individual_scores_insert on public.individual_scores;
create policy individual_scores_insert on public.individual_scores for insert to authenticated with check(judge_id=auth.uid() and public.current_role()='judge');
drop policy if exists individual_scores_update on public.individual_scores;
create policy individual_scores_update on public.individual_scores for update to authenticated using(judge_id=auth.uid() or public.is_admin()) with check(judge_id=auth.uid() or public.is_admin());

grant select on public.app_roles,public.debate_sessions,public.debate_groups,public.debate_members to anon,authenticated;
grant insert,update,delete on public.app_roles,public.debate_sessions,public.debate_groups,public.debate_members to authenticated;
grant select on public.user_profiles to authenticated;
grant select,insert,update,delete on public.user_profiles to authenticated;
grant select,insert,update on public.team_scores,public.individual_scores to authenticated;
grant execute on function public.current_role() to authenticated;
grant execute on function public.is_admin() to authenticated;

DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['debate_sessions','debate_groups','debate_members','team_scores','individual_scores','app_roles'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_publication_tables WHERE pubname='supabase_realtime' AND schemaname='public' AND tablename=t) THEN
   EXECUTE format('ALTER PUBLICATION supabase_realtime ADD TABLE public.%I',t);
  END IF;
 END LOOP;
END $$;

insert into public.debate_sessions(title,topic,session_date,status)
select 'نخستین دوره مناظره کلاسی','موضوع مناظره پس از ثبت توسط مدیر نمایش داده می‌شود.',current_date,'scheduled'
where not exists(select 1 from public.debate_sessions);

create or replace function public.publish_debate_session(p_session_id uuid)
returns void language plpgsql security definer set search_path=public
as $$
declare judge_total integer; group_total integer; member_total integer;
begin
 if not public.is_admin() then raise exception 'admin only'; end if;
 select count(*) into judge_total from public.user_profiles where role_key='judge' and active=true;
 if judge_total<>5 then raise exception 'برای انتشار نتایج باید دقیقاً پنج حساب داوری فعال وجود داشته باشد.'; end if;
 select count(*) into group_total from public.debate_groups where session_id=p_session_id;
 select count(*) into member_total from public.debate_members where session_id=p_session_id;
 if group_total=0 or member_total=0 then raise exception 'ابتدا گروه‌ها و اعضای دوره را کامل کنید.'; end if;
 if exists(select 1 from public.debate_groups g where g.session_id=p_session_id and (select count(distinct s.judge_id) from public.team_scores s where s.group_id=g.id and s.session_id=p_session_id)<>5) then raise exception 'امتیاز تیمی همه گروه‌ها باید توسط هر پنج داور ثبت شود.'; end if;
 if exists(select 1 from public.debate_members m where m.session_id=p_session_id and (select count(distinct s.judge_id) from public.individual_scores s where s.member_id=m.id and s.session_id=p_session_id)<>5) then raise exception 'امتیاز فردی همه اعضا باید توسط هر پنج داور ثبت شود.'; end if;
 update public.debate_sessions set published=true,updated_at=now() where id=p_session_id;
end $$;
grant execute on function public.publish_debate_session(uuid) to authenticated;

drop policy if exists team_scores_published_read on public.team_scores;
create policy team_scores_published_read on public.team_scores for select to anon,authenticated using(exists(select 1 from public.debate_sessions s where s.id=session_id and s.published=true));
drop policy if exists individual_scores_published_read on public.individual_scores;
create policy individual_scores_published_read on public.individual_scores for select to anon,authenticated using(exists(select 1 from public.debate_sessions s where s.id=session_id and s.published=true));
grant select on public.team_scores,public.individual_scores to anon;
