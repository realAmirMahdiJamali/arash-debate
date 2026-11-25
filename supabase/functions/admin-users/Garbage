import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS"
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405, headers: { ...cors, "Content-Type": "application/json" } });
  try {
    const url = Deno.env.get("SUPABASE_URL")!;
    const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
    const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const authHeader = req.headers.get("Authorization") || "";
    const authClient = createClient(url, anon, { global: { headers: { Authorization: authHeader } } });
    const { data: { user }, error: authError } = await authClient.auth.getUser();
    if (authError || !user) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: { ...cors, "Content-Type": "application/json" } });
    const { data: profile } = await authClient.from("user_profiles").select("role").eq("id", user.id).single();
    if (profile?.role !== "admin") return new Response(JSON.stringify({ error: "Admin access required" }), { status: 403, headers: { ...cors, "Content-Type": "application/json" } });
    const body = await req.json();
    const studentId = String(body.student_id || "").trim();
    const role = String(body.role || "");
    const initialPassword = String(body.initial_password || "");
    const observerGroup = Number(body.observer_group || 1);
    if (!/^\d{5,20}$/.test(studentId)) throw new Error("شماره دانشجویی معتبر نیست.");
    if (!["judge", "observer"].includes(role)) throw new Error("نقش کاربر معتبر نیست.");
    if (initialPassword.length < 8 || initialPassword.length > 64) throw new Error("گذرواژه اولیه باید حداقل ۸ نویسه باشد.");
    if (role === "observer" && (!Number.isInteger(observerGroup) || observerGroup < 1 || observerGroup > 4)) throw new Error("گروه مشاهده‌گر معتبر نیست.");
    const admin = createClient(url, service);
    if (role === "judge") {
      const { count, error: countError } = await admin.from("user_profiles").select("id", { count: "exact", head: true }).eq("role", "judge");
      if (countError) throw countError;
      if ((count || 0) >= 5) throw new Error("ظرفیت پنج حساب داوری تکمیل شده است.");
    }
    const email = `${studentId}@users.arashgroup.invalid`;
    const { data, error } = await admin.auth.admin.createUser({
      email,
      password: initialPassword,
      email_confirm: true,
      user_metadata: { student_id: studentId, role, observer_group: role === "observer" ? observerGroup : null, force_password_change: true }
    });
    if (error) throw error;
    return new Response(JSON.stringify({ id: data.user.id, student_id: studentId, role }), { status: 201, headers: { ...cors, "Content-Type": "application/json" } });
  } catch (error) {
    return new Response(JSON.stringify({ error: error instanceof Error ? error.message : "Unexpected error" }), { status: 400, headers: { ...cors, "Content-Type": "application/json" } });
  }
});
