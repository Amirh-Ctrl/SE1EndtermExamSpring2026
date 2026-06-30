# Q7 - Secure Messenger Code

این پوشه پاسخ سؤال ۷ است. کد نرم‌افزار پیام‌رسان با رمزگذاری انتهابه‌انتها داخل دایرکتوری شماره دانشجویی قرار گرفته است و ساختار آن با معماری ارائه‌شده در بخش نظری هماهنگ است.

## محتوا

- `src/secure_messenger/crypto`: رمزنگاری انتهابه‌انتها با X25519، HKDF-SHA256 و ChaCha20-Poly1305
- `src/secure_messenger/domain`: مدل‌ها و خطاهای دامنه
- `src/secure_messenger/server`: سرویس کاربردی، مخزن SQLite و HTTP API
- `src/secure_messenger/client`: کلاینت HTTP و نگهداری profile محلی
- `src/secure_messenger/cli.py`: رابط خط فرمان برای اجرای سناریوهای اصلی
- `docs`: مستندات معماری، ER، امنیت و API
- `Dockerfile`: آماده برای استفاده در سؤال CD

## اجرای نمونه

```powershell
cd 40031701
$env:PYTHONPATH="src"
python -m secure_messenger server --host 127.0.0.1 --port 8080 --db data/messenger.db
```

در یک ترمینال دیگر:

```powershell
cd 40031701
$env:PYTHONPATH="src"
python -m secure_messenger init-user alice --password alice-pass-123 --server-url http://127.0.0.1:8080 --profiles-dir profiles
python -m secure_messenger init-user bob --password bob-pass-123 --server-url http://127.0.0.1:8080 --profiles-dir profiles
python -m secure_messenger send alice bob --message "سلام باب" --password alice-pass-123 --server-url http://127.0.0.1:8080 --profiles-dir profiles
python -m secure_messenger inbox bob --password bob-pass-123 --server-url http://127.0.0.1:8080 --profiles-dir profiles
```

## نکته تحویل

برای سؤال ۷، همین پوشه‌ی `40031701` باید در ریشه repo و روی branch اصلی قرار بگیرد. تست‌ها، ابزار coverage و GitHub Actions مربوط به سؤال‌های ۸ تا ۱۰ هستند و در بسته‌ی Q7 جدا نشده‌اند.

