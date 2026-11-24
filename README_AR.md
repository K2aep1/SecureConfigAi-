# هوية SecureConfigAI — حزمة العلامة البصرية

## ما تتضمنه الحزمة

- `frontend/public/favicon.svg`: أيقونة تبويب المتصفح بدلاً من أيقونة Vite.
- `frontend/public/secureconfigai-mark.svg`: الأيقونة وحدها للاستخدامات الصغيرة.
- `frontend/public/secureconfigai-wordmark.svg`: شعار كامل بصيغة SVG.
- `frontend/src/components/SecureConfigAILogo.tsx`: مكوّن React قابل لإعادة الاستخدام للشريط الجانبي أو صفحات تسجيل الدخول.
- `frontend/src/brand.css`: أنماط الشعار وألوان الهوية وخطوط الواجهة.
- `frontend/index.html`: مثال كامل لربط الـfavicon وخط Inter وخط IBM Plex Mono.
- `APP_SHELL_REPLACEMENT.txt`: تعليمات دمج الشعار في `AppShell.tsx` من دون استبدال الملف بالكامل.

## الهوية المقترحة

- **Inter:** خط الواجهة والعناوين والأزرار والجداول؛ حديث وواضح في واجهات SaaS.
- **IBM Plex Mono:** للأدلة التقنية ومعرّفات الضوابط والقيم التقنية.
- **Navy `#10243E`:** اللون الرئيسي للعلامة.
- **Cyan `#45E0CF`:** اللون المميز للشعار والتفاصيل الدقيقة.
- **Blue `#3977F6`:** اللون المقترح للإجراءات الأساسية والروابط النشطة.
- **Light neutral `#F4F7FB`:** خلفية واجهة هادئة، مع إبقاء ألوان الـseverity محجوزة لمعانيها الأمنية.

هذه تغييرات في الهوية البصرية فقط؛ لا تغيّر إعدادات Gemini أو APIs أو قاعدة البيانات أو منطق الـFindings.

## خطوات الدمج الآمنة

1. أوقف الـFrontend وخذ نسخة احتياطية من مجلد `frontend`.
2. انسخ `frontend/public/favicon.svg` و`frontend/public/secureconfigai-mark.svg` إلى `public` الموجود في مشروعك.
3. انسخ `frontend/src/components/SecureConfigAILogo.tsx` إلى `src/components`، وانسخ `frontend/src/brand.css` إلى `src`.
4. افتح `APP_SHELL_REPLACEMENT.txt` وطبّق تعليمات استبدال كتلة الشعار في `AppShell.tsx` فقط؛ لا تستبدل AppShell كاملاً لتجنب فقد الوظائف الموجودة لديك.
5. أضف رابط favicon وروابط Inter وIBM Plex Mono إلى `<head>` في `frontend/index.html`، واحذف أي رابط يشير إلى `/vite.svg`. الملف الموجود في هذه الحزمة نموذج كامل؛ إذا كان ملفك يحتوي إعدادات إضافية مهمة فانسخ عناصر `<head>` فقط بدلاً من استبداله كلياً.
6. شغّل من مجلد `frontend`:

   ```powershell
   npm run typecheck
   npm run build
   ```

7. شغّل الواجهة وجرّب تسجيل الدخول والفحص وAI Assistant. إذا لم يتغيّر رمز التبويب فوراً، نفّذ تحديثاً قسرياً للمتصفح `Ctrl+F5`.

## ملاحظات

- لا تحتوي الحزمة على مفتاح API ولا ملف `.env`.
- تحميل الخطوط من Google Fonts يحتاج اتصالاً بالإنترنت؛ إذا أردت تشغيل الواجهة دون إنترنت، أبقِ خطوط النظام كبديل أو استضف ملفات الخطوط محلياً وفق تراخيصها.
- لم أستبدل تطبيقك كاملاً، لأن إصدار `AppShell.tsx` لديك قد يحتوي تغييرات وظيفية حصلت بعد النسخة التي جرى فحصها. تعليمات الدمج تستهدف استبدال كتلة العلامة فقط.
