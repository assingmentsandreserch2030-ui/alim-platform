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
    if (!Number.isInteger(out.grade) || out.grade < 1 || out.grade > 12) return { error: "اختر الصف" };
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

// يقرأ كلمة المرور حتى لو كُتب اسم المتغير بحروف صغيرة أو بمسافة زائدة
function adminPassword(env) {
  if (typeof env.ADMIN_PASSWORD === "string" && env.ADMIN_PASSWORD.trim()) return env.ADMIN_PASSWORD;
  for (const [k, v] of Object.entries(env)) {
    if (typeof v === "string" && v.trim() && /PASS|PASSWORD|كلمة/i.test(k.replace(/[^A-Za-z\u0600-\u06FF]/g, ""))) return v;
  }
  return "";
}
function missingPassword(env) {
  const names = Object.entries(env).filter(([, v]) => typeof v === "string").map(([k]) => k);
  return json({
    error: "لم تُضبط كلمة مرور الإدارة بعد في إعدادات Cloudflare (ADMIN_PASSWORD)",
    seen: names.length ? "المتغيرات التي يراها الموقع: " + names.join("، ") : "الموقع لا يرى أي متغير",
  }, 503);
}

async function login(request, env) {
  const ADMIN = adminPassword(env);
  if (!ADMIN) return missingPassword(env);
  let body = {};
  try { body = await request.json(); } catch {}
  const pass = normPass(body.password);
  // مقارنة بصمتين متساويتي الطول حتى لا يُستدل على كلمة المرور من زمن الاستجابة
  const ok = safeEqual(await hmac("alim-check", pass), await hmac("alim-check", normPass(ADMIN)));
  if (!ok) {
    await new Promise((r) => setTimeout(r, 800));
    return json({ error: "كلمة المرور غير صحيحة" }, 401);
  }
  const exp = Date.now() + TOKEN_HOURS * 3600 * 1000;
  const payload = String(exp);
  return json({ token: payload + "." + (await hmac(ADMIN, payload)), exp });
}

async function guard(request, env, fn) {
  const ADMIN = adminPassword(env);
  if (!ADMIN) return missingPassword(env);
  const auth = request.headers.get("authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const [payload, sig] = token.split(".");
  const valid = payload && sig && Number(payload) > Date.now() && safeEqual(sig, await hmac(ADMIN, payload));
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
  return json({ items });
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
