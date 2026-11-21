import { DurableObject } from "cloudflare:workers";

// خادم منصة علِّم: يخدم صفحات الموقع، ويحفظ الملفات المرفوعة من صفحة الإدارة في Cloudflare KV.
// المسارات:
//   GET    /api/items?grade=&subject=   قائمة الملفات (عامة)
//   POST   /api/login                   تسجيل دخول المدير بكلمة المرور
//   POST   /api/items                   رفع ملف جديد (للمدير)
//   PATCH  /api/items/:id               تعديل بيانات ملف أو استبدال الملف (للمدير)
//   DELETE /api/items/:id               حذف ملف (للمدير)
//   GET    /files/:id/:name             عرض الملف أو تنزيله (عام)

const MAX_BYTES = 25 * 1024 * 1024; // أقصى حجم لقيمة واحدة في KV
const TOKEN_HOURS = 12;
const TYPES = ["book", "review", "work"];
const AUDIENCES = ["all", "teacher"];
const INDEX_KEY = "index";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    try {
      if (path.startsWith("/files/")) return serveFile(request, env, path);
      if (path === "/api/login" && request.method === "POST") return login(request, env);
      if (path === "/api/setup" && request.method === "POST") return setup(request, env);
      if (path === "/api/visit" || path === "/api/visits") return visits(request, env, path);
      if (path === "/api/items" && request.method === "GET") return listItems(env, url);
      if (path === "/api/items" && request.method === "POST") return guard(request, env, () => createItem(request, env));
      const m = path.match(/^\/api\/items\/([a-z0-9]+)$/);
      if (m && request.method === "PATCH") return guard(request, env, () => updateItem(request, env, m[1]));
      if (m && request.method === "DELETE") return guard(request, env, () => deleteItem(env, m[1]));
      if (path === "/api/session" && request.method === "GET") return guard(request, env, () => json({ ok: true }));
      if (path.startsWith("/api/")) return json({ error: "المسار غير موجود" }, 404);
      return env.ASSETS.fetch(request);
    } catch (err) {
      console.error(err);
      return json({ error: "حدث خطأ في الخادم، حاول مرة أخرى" }, 500);
    }
  },
};

// ---------- أدوات عامة ----------
function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra },
  });
}

async function readIndex(env) {
  return (await env.FILES.get(INDEX_KEY, { type: "json" })) || [];
}
async function writeIndex(env, items) {
  await env.FILES.put(INDEX_KEY, JSON.stringify(items));
}

function newId() {
  const b = crypto.getRandomValues(new Uint8Array(9));
  return Date.now().toString(36) + Array.from(b, (x) => x.toString(36).padStart(2, "0")).join("").slice(0, 10);
}

function clean(s, max = 200) {
  return String(s ?? "").replace(/[\u0000-\u001f]/g, " ").trim().slice(0, max);
}

// يتحقق من البيانات ويعيد نسخة نظيفة، أو رسالة خطأ
function validateMeta(input, partial = false) {
  const out = {};
  const has = (k) => input[k] !== undefined && input[k] !== null;
  if (!partial || has("title")) {
    out.title = clean(input.title, 150);
    if (!out.title) return { error: "اكتب عنوان الملف" };
  }
  if (!partial || has("desc")) out.desc = clean(input.desc, 300);
  if (!partial || has("grade")) {
    out.grade = Number(input.grade);
    // الصف 0 مخصص للقاعدة النورانية
    if (!Number.isInteger(out.grade) || out.grade < 0 || out.grade > 12) return { error: "اختر الصف" };
  }
  if (!partial || has("subject")) {
    out.subject = clean(input.subject, 30);
    if (!/^[a-z]+$/.test(out.subject)) return { error: "اختر المادة" };
  }
  if (!partial || has("term")) {
    out.term = Number(input.term);
    if (out.term !== 1 && out.term !== 2) return { error: "اختر الفصل الدراسي" };
  }
  if (!partial || has("type")) {
    out.type = clean(input.type, 20);
    if (!TYPES.includes(out.type)) return { error: "اختر نوع الملف" };
  }
  if (!partial || has("audience")) {
    out.audience = clean(input.audience || "all", 20);
    if (!AUDIENCES.includes(out.audience)) return { error: "اختر لمن الملف" };
  }
  return { meta: out };
}

function fileLabel(name) {
  const ext = (String(name).split(".").pop() || "").toUpperCase();
  return ext && ext.length <= 5 ? ext : "ملف";
}

// ---------- الدخول ----------
async function hmac(secret, data) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function safeEqual(a, b) {
  const ea = new TextEncoder().encode(a), eb = new TextEncoder().encode(b);
  let diff = ea.length ^ eb.length;
  for (let i = 0; i < Math.max(ea.length, eb.length); i++) diff |= (ea[i] || 0) ^ (eb[i] || 0);
  return diff === 0;
}

// يتسامح مع الفروق الشائعة: المسافات في البداية والنهاية، وعلامات الاقتباس، والأرقام العربية ٠-٩ والفارسية ۰-۹
function normPass(v) {
  let s = String(v ?? "").normalize("NFC").trim();
  if (s.length >= 2 && /^["'].*["']$/.test(s)) s = s.slice(1, -1).trim();
  return s.replace(/[\u0660-\u0669]/g, (d) => String(d.charCodeAt(0) - 0x660)).replace(/[\u06F0-\u06F9]/g, (d) => String(d.charCodeAt(0) - 0x6f0));
}

// يقرأ كلمة المرور من متغير سري إن وُجد، حتى لو كُتب اسمه بحروف صغيرة أو بمسافة زائدة
function envPassword(env) {
  if (typeof env.ADMIN_PASSWORD === "string" && env.ADMIN_PASSWORD.trim()) return env.ADMIN_PASSWORD;
  for (const [k, v] of Object.entries(env)) {
    if (typeof v === "string" && v.trim() && /PASS/i.test(k)) return v;
  }
  return "";
}

// كلمة المرور التي اختارها المدير من صفحة الإعداد تُحفظ في KV كبصمة PBKDF2 فقط
const AUTH_KEY = "admin:auth";
const b64 = (u8) => btoa(String.fromCharCode(...u8));
async function pbkdf2(pass, saltB64, iter) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveBits"]);
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, key, 256);
  return b64(new Uint8Array(bits));
}
async function sha256hex(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, "0")).join("");
}

// يعيد مفتاح توقيع الجلسات ودالة التحقق من كلمة المرور، أو null إن لم تُضبط بعد
async function getAuth(env) {
  const ep = envPassword(env);
  if (ep) return { key: "env:" + ep, check: async (p) => safeEqual(await hmac("alim-check", normPass(p)), await hmac("alim-check", normPass(ep))) };
  const rec = await env.FILES.get(AUTH_KEY, { type: "json", cacheTtl: 60 });
  if (rec && rec.hash) return { key: "kv:" + rec.hash, check: async (p) => safeEqual(await pbkdf2(normPass(p), rec.salt, rec.iter), rec.hash) };
  return null;
}

async function issueToken(key) {
  const exp = Date.now() + TOKEN_HOURS * 3600 * 1000;
  const payload = String(exp);
  return { token: payload + "." + (await hmac(key, payload)), exp };
}

async function login(request, env) {
  const auth = await getAuth(env);
  if (!auth) return json({ error: "لم تُختر كلمة مرور الإدارة بعد. اختر «تعيين كلمة المرور» واكتب رمز الإعداد.", needSetup: true }, 503);
  let body = {};
  try { body = await request.json(); } catch {}
  if (!(await auth.check(body.password))) {
    await new Promise((r) => setTimeout(r, 800));
    return json({ error: "كلمة المرور غير صحيحة" }, 401);
  }
  return json(await issueToken(auth.key));
}

// تعيين كلمة المرور أول مرة، أو إعادة تعيينها عند نسيانها، برمز الإعداد
async function setup(request, env) {
  let body = {};
  try { body = await request.json(); } catch {}
  const code = normPass(body.code).toUpperCase().replace(/[^A-Z0-9]/g, "");
  const okCode = env.SETUP_CODE_HASH && code && safeEqual(await sha256hex(code), String(env.SETUP_CODE_HASH));
  if (!okCode) {
    await new Promise((r) => setTimeout(r, 1200));
    return json({ error: "رمز الإعداد غير صحيح" }, 401);
  }
  if (envPassword(env)) return json({ error: "يوجد متغير سري لكلمة المرور في Cloudflare، وهو المعتمد. ادخل به أو احذفه من الإعدادات." }, 409);
  const pass = normPass(body.password);
  if (pass.length < 6) return json({ error: "اختر كلمة مرور من 6 أحرف أو أرقام على الأقل" }, 400);
  const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  const iter = 100000;
  const hash = await pbkdf2(pass, salt, iter);
  await env.FILES.put(AUTH_KEY, JSON.stringify({ salt, iter, hash, set: Date.now() }));
  return json(await issueToken("kv:" + hash));
}

async function guard(request, env, fn) {
  const auth = await getAuth(env);
  if (!auth) return json({ error: "لم تُختر كلمة مرور الإدارة بعد", needSetup: true }, 503);
  const h = request.headers.get("authorization") || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  const [payload, sig] = token.split(".");
  const valid = payload && sig && Number(payload) > Date.now() && safeEqual(sig, await hmac(auth.key, payload));
  if (!valid) return json({ error: "انتهت الجلسة، سجّل الدخول من جديد" }, 401);
  return fn();
}

// ---------- القائمة العامة ----------
async function listItems(env, url) {
  let items = await readIndex(env);
  const grade = url.searchParams.get("grade");
  const subject = url.searchParams.get("subject");
  if (grade) items = items.filter((i) => String(i.grade) === grade);
  if (subject) items = items.filter((i) => i.subject === subject);
  items.sort((a, b) => b.created - a.created);
  return json({ items }, 200, CORS);
}

// ---------- الرفع والتعديل والحذف ----------
async function readFilePart(form) {
  const file = form.get("file");
  if (!file || typeof file === "string" || !file.size) return { none: true };
  if (file.size > MAX_BYTES) return { error: "حجم الملف أكبر من 25 ميغابايت" };
  return { file, buf: await file.arrayBuffer() };
}

async function createItem(request, env) {
  const form = await request.formData();
  const v = validateMeta(Object.fromEntries([...form.entries()].filter(([k]) => k !== "file")));
  if (v.error) return json({ error: v.error }, 400);
  const f = await readFilePart(form);
  if (f.error) return json({ error: f.error }, 413);
  if (f.none) return json({ error: "اختر ملفًا لرفعه" }, 400);

  const id = newId();
  const now = Date.now();
  const fileName = clean(f.file.name, 120) || "file";
  const contentType = f.file.type || "application/octet-stream";
  await env.FILES.put("file:" + id, f.buf, { metadata: { contentType, fileName } });
  const item = { id, ...v.meta, fileName, label: fileLabel(fileName), size: f.file.size, contentType, created: now, updated: now };
  const items = await readIndex(env);
  items.push(item);
  await writeIndex(env, items);
  return json({ item }, 201);
}

async function updateItem(request, env, id) {
  const items = await readIndex(env);
  const idx = items.findIndex((i) => i.id === id);
  if (idx < 0) return json({ error: "الملف غير موجود" }, 404);

  let input = {}, f = { none: true };
  const ct = request.headers.get("content-type") || "";
  if (ct.includes("multipart/form-data")) {
    const form = await request.formData();
    input = Object.fromEntries([...form.entries()].filter(([k]) => k !== "file"));
    f = await readFilePart(form);
    if (f.error) return json({ error: f.error }, 413);
  } else {
    try { input = await request.json(); } catch {}
  }
  const v = validateMeta(input, true);
  if (v.error) return json({ error: v.error }, 400);

  const item = { ...items[idx], ...v.meta, updated: Date.now() };
  if (!f.none) {
    item.fileName = clean(f.file.name, 120) || "file";
    item.label = fileLabel(item.fileName);
    item.size = f.file.size;
    item.contentType = f.file.type || "application/octet-stream";
    await env.FILES.put("file:" + id, f.buf, { metadata: { contentType: item.contentType, fileName: item.fileName } });
  }
  items[idx] = item;
  await writeIndex(env, items);
  return json({ item });
}

async function deleteItem(env, id) {
  const items = await readIndex(env);
  const rest = items.filter((i) => i.id !== id);
  if (rest.length === items.length) return json({ error: "الملف غير موجود" }, 404);
  await writeIndex(env, rest);
  await env.FILES.delete("file:" + id);
  return json({ ok: true });
}

// ---------- عرض الملفات ----------
async function serveFile(request, env, path) {
  const m = path.match(/^\/files\/([a-z0-9]+)(?:\/.*)?$/);
  if (!m) return new Response("غير موجود", { status: 404 });
  const { value, metadata } = await env.FILES.getWithMetadata("file:" + m[1], { type: "stream" });
  if (!value) return new Response("الملف غير موجود أو حُذف", { status: 404, headers: { "content-type": "text/plain; charset=utf-8" } });
  const name = (metadata && metadata.fileName) || "file";
  const type = (metadata && metadata.contentType) || "application/octet-stream";
  // صفحات الويب والصور المتجهة تُنزَّل ولا تُفتح داخل الموقع، حتى لا تُشغَّل فيه أي شيفرة
  const risky = /html|svg|xml|javascript/i.test(type);
  const download = risky || new URL(request.url).searchParams.has("download");
  return new Response(value, {
    headers: {
      "content-type": risky ? "application/octet-stream" : type,
      "content-disposition": `${download ? "attachment" : "inline"}; filename*=UTF-8''${encodeURIComponent(name)}`,
      "cache-control": "public, max-age=300",
      "x-content-type-options": "nosniff",
    },
  });
}

// ---------- عدّاد الزوار ----------
// كائن واحد دائم يحفظ العدد الكلي وعدد زوار اليوم (بتوقيت قطر). كل متصفح يُحسب مرة واحدة في اليوم.
export class VisitCounter extends DurableObject {
  async fetch(request) {
    const day = new Date(Date.now() + 3 * 3600 * 1000).toISOString().slice(0, 10);
    let s = (await this.ctx.storage.get("s")) || { total: 0, day, today: 0 };
    if (s.day !== day) s = { ...s, day, today: 0 };
    if (request.method === "POST") {
      s.total++;
      s.today++;
      await this.ctx.storage.put("s", s);
    }
    return Response.json({ total: s.total, today: s.today });
  }
}

const CORS = { "access-control-allow-origin": "*", "access-control-allow-methods": "GET, POST, OPTIONS" };
async function visits(request, env, path) {
  if (request.method === "OPTIONS") return new Response(null, { headers: CORS });
  if (!env.VISITS) return json({ total: 0, today: 0 }, 200, CORS);
  const stub = env.VISITS.get(env.VISITS.idFromName("site"));
  const ua = request.headers.get("user-agent") || "";
  const bot = /bot|crawl|spider|slurp|preview|monitor|curl|wget|python|headless/i.test(ua);
  const add = path === "/api/visit" && request.method === "POST" && !bot;
  const res = await stub.fetch("https://counter/", { method: add ? "POST" : "GET" });
  return json(await res.json(), 200, CORS);
}
