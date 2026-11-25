import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
const cors={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type","Access-Control-Allow-Methods":"POST, OPTIONS"};
const reply=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{...cors,"Content-Type":"application/json"}});
Deno.serve(async(req)=>{
 if(req.method==="OPTIONS")return new Response("ok",{headers:cors});
 if(req.method!=="POST")return reply({error:"Method not allowed"},405);
 try{
  const url=Deno.env.get("SUPABASE_URL")!,anon=Deno.env.get("SUPABASE_ANON_KEY")!,service=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const admin=createClient(url,service,{auth:{autoRefreshToken:false,persistSession:false}});
  const body=await req.json(),action=String(body.action||"");
  if(action==="login"){
   const username=String(body.username??""),password=String(body.password??"");
   if(!username||!password)return reply({error:"نام کاربری و گذرواژه الزامی است."},400);
   const {data:profile,error:pErr}=await admin.from("user_profiles").select("id,active,username").eq("username",username).maybeSingle();
   if(pErr||!profile||!profile.active)return reply({error:"نام کاربری یا گذرواژه نادرست است."},401);
   const {data:userData,error:uErr}=await admin.auth.admin.getUserById(profile.id);
   if(uErr||!userData.user?.email)return reply({error:"حساب کاربری معتبر نیست."},401);
   const loginClient=createClient(url,anon,{auth:{autoRefreshToken:false,persistSession:false}});
   const {data,error}=await loginClient.auth.signInWithPassword({email:userData.user.email,password});
   if(error||!data.session)return reply({error:"نام کاربری یا گذرواژه نادرست است."},401);
   return reply({session:data.session,user:data.user});
  }
  const authHeader=req.headers.get("Authorization")||"";
  const authClient=createClient(url,anon,{global:{headers:{Authorization:authHeader}}});
  const {data:{user},error:authError}=await authClient.auth.getUser();
  if(authError||!user)return reply({error:"ابتدا وارد حساب شوید."},401);
  const {data:me}=await admin.from("user_profiles").select("role_key,active").eq("id",user.id).single();
  if(me?.role_key!=="admin"||!me.active)return reply({error:"دسترسی مدیر لازم است."},403);
  if(action==="create"){
   const username=String(body.username||""),password=String(body.password||""),role=String(body.role_key||"participant"),display=String(body.display_name||"");
   if(!/^[A-Za-z0-9_.-]{3,32}$/.test(username))throw new Error("نام کاربری باید ۳ تا ۳۲ نویسه و شامل حروف لاتین، عدد، نقطه، خط تیره یا زیرخط باشد.");
   if(password.length<10)throw new Error("گذرواژه باید حداقل ۱۰ نویسه باشد.");
   const {data:roleRow}=await admin.from("app_roles").select("role_key").eq("role_key",role).single();if(!roleRow)throw new Error("نقش انتخاب‌شده معتبر نیست.");
   if(role==="judge"){const {count}=await admin.from("user_profiles").select("id",{count:"exact",head:true}).eq("role_key","judge").eq("active",true);if((count||0)>=5)throw new Error("حداکثر پنج حساب داوری فعال مجاز است.");}
   const email=`${crypto.randomUUID()}@login.arashdebate.invalid`;
   const {data:created,error}=await admin.auth.admin.createUser({email,password,email_confirm:true});if(error)throw error;
   const {error:insertError}=await admin.from("user_profiles").insert({id:created.user.id,username,display_name:display,role_key:role});
   if(insertError){await admin.auth.admin.deleteUser(created.user.id);throw insertError;}
   return reply({ok:true,id:created.user.id});
  }
  if(action==="update"){
   const id=String(body.id||""),patch:Record<string,unknown>={};
   if(body.username!==undefined){const username=String(body.username);if(!/^[A-Za-z0-9_.-]{3,32}$/.test(username))throw new Error("نام کاربری معتبر نیست.");patch.username=username;}
   if(body.display_name!==undefined)patch.display_name=String(body.display_name);
   if(body.role_key!==undefined){const role=String(body.role_key);const {data:r}=await admin.from("app_roles").select("role_key").eq("role_key",role).single();if(!r)throw new Error("نقش معتبر نیست.");if(role==="judge"){const {count}=await admin.from("user_profiles").select("id",{count:"exact",head:true}).eq("role_key","judge").eq("active",true).neq("id",id);if((count||0)>=5)throw new Error("ظرفیت پنج حساب داوری فعال تکمیل است.");}patch.role_key=role;}
   if(body.active!==undefined)patch.active=!!body.active;
   if(patch.role_key!==undefined||patch.active!==undefined){const {data:current}=await admin.from("user_profiles").select("role_key,active").eq("id",id).single();const nextRole=String(patch.role_key??current?.role_key??"");const nextActive=Boolean(patch.active??current?.active);if(nextRole==="judge"&&nextActive){const {count}=await admin.from("user_profiles").select("id",{count:"exact",head:true}).eq("role_key","judge").eq("active",true).neq("id",id);if((count||0)>=5)throw new Error("ظرفیت پنج حساب داوری فعال تکمیل است.");}}
   if(Object.keys(patch).length){patch.updated_at=new Date().toISOString();const {error}=await admin.from("user_profiles").update(patch).eq("id",id);if(error)throw error;}
   if(body.password){const password=String(body.password);if(password.length<10)throw new Error("گذرواژه باید حداقل ۱۰ نویسه باشد.");const {error}=await admin.auth.admin.updateUserById(id,{password});if(error)throw error;}
   return reply({ok:true});
  }
  if(action==="delete"){
   const id=String(body.id||"");if(id===user.id)throw new Error("مدیر نمی‌تواند حساب خودش را حذف کند.");
   const {data:target}=await admin.from("user_profiles").select("role_key").eq("id",id).single();if(target?.role_key==="admin")throw new Error("حذف حساب مدیر از این بخش مجاز نیست.");
   const {error}=await admin.auth.admin.deleteUser(id);if(error)throw error;return reply({ok:true});
  }
  return reply({error:"عملیات ناشناخته است."},400);
 }catch(error){return reply({error:error instanceof Error?error.message:"خطای پیش‌بینی‌نشده"},400);}
});
