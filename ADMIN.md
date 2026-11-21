# صفحة إدارة منصة علِّم

الرابط: https://alim-platform.assingmentsandreserch2030.workers.dev/admin

## ضبط كلمة المرور (مرة واحدة)
1. ادخل إلى dash.cloudflare.com
2. Workers & Pages ← alim-platform ← Settings
3. في قسم Variables and Secrets اضغط Add
4. النوع Secret، الاسم `ADMIN_PASSWORD`، والقيمة كلمة المرور التي تريدها
5. اضغط Deploy

## كيف تعمل
- الملفات وبياناتها محفوظة في Cloudflare KV باسم `alim-files` (حتى 25 ميغابايت للملف).
- كل ملف مرتبط بالصف والمادة والفصل والنوع، ويظهر تلقائيًا في صفحة المادة في الموقع.
- الخادم في `src/worker.js`، وصفحة الإدارة في `admin.html`.
