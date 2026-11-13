import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

import pymysql
from pymysql.cursors import DictCursor
from flask import (
    Flask, render_template_string, request, redirect, url_for, session, abort, Response,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from zoneinfo import ZoneInfo
    LOCAL_TZ = ZoneInfo('Asia/Jerusalem')
except Exception:   # لو لم تتوفر قاعدة المناطق الزمنية
    LOCAL_TZ = timezone(timedelta(hours=2))

# ----------------------------------------------------------------------
# الإعدادات
# ----------------------------------------------------------------------
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

ON_RENDER = bool(os.environ.get("RENDER"))

_secret = os.environ.get("SECRET_KEY")
if not _secret:
    if ON_RENDER:
        raise RuntimeError("يجب ضبط متغير البيئة SECRET_KEY على Render.")
    _secret = secrets.token_hex(32)
app.secret_key = _secret

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=ON_RENDER,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),   # تنتهي بعد 30 دقيقة بدون نشاط
    MAX_CONTENT_LENGTH=64 * 1024,
)

_missing = [n for n in ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD") if not os.environ.get(n)]
if _missing:
    raise RuntimeError("متغيرات البيئة التالية ناقصة: " + ", ".join(_missing))

DB_CONFIG = dict(
    host=os.environ["DB_HOST"],
    user=os.environ["DB_USER"],
    password=os.environ["DB_PASSWORD"],
    database=os.environ["DB_NAME"],
    port=int(os.environ.get("DB_PORT", "3306")),
    charset="utf8mb4",
    cursorclass=DictCursor,
    connect_timeout=10,
    autocommit=False,
)

USER_KEY = 'eid'
USER_NAME = 'عيد'
# اسم الدخول المقبول: بالعربي أو بالإنجليزي
LOGIN_NAMES = {'عيد': USER_KEY, 'eid': USER_KEY}

MIN_PASSWORD_LEN = 8
MAX_FAILS = 5
FAIL_WINDOW = 15 * 60
TEMP_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
MAX_MONEY = Decimal('9999999.99')
MAX_QTY = 1000000


def local_now():
    """الوقت المحلي (فلسطين) بدون معلومات المنطقة، كما يُحفظ في القاعدة."""
    return datetime.now(LOCAL_TZ).replace(tzinfo=None, microsecond=0)


# ----------------------------------------------------------------------
# قاعدة البيانات
# ----------------------------------------------------------------------
def _connect():
    return pymysql.connect(**DB_CONFIG)


def _run(sql, params=(), fetch=None):
    conn = _connect()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            if fetch == "one":
                result = cur.fetchone()
            elif fetch == "all":
                result = cur.fetchall()
            else:
                result = cur.rowcount
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _tx(work):
    """ينفّذ عدة أوامر كعملية واحدة (كلها أو لا شيء). work(cur) يرجع نتيجة."""
    conn = _connect()
    try:
        with conn.cursor() as cur:
            result = work(cur)
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def new_temp_password():
    return ''.join(secrets.choice(TEMP_ALPHABET) for _ in range(10))


def init_db():
    tail = "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    _run(
        "CREATE TABLE IF NOT EXISTS tyre_users ("
        "user_key VARCHAR(50) NOT NULL PRIMARY KEY,"
        "display_name VARCHAR(100) NOT NULL,"
        "password_hash VARCHAR(255) NOT NULL,"
        "must_change TINYINT(1) NOT NULL DEFAULT 1,"
        "reset_marker VARCHAR(64) NOT NULL DEFAULT ''"
        ") " + tail
    )
    _run(
        "CREATE TABLE IF NOT EXISTS tyre_items ("
        "name VARCHAR(150) NOT NULL PRIMARY KEY,"
        "qty INT NOT NULL DEFAULT 0,"
        "buy_price DECIMAL(10,2) NOT NULL DEFAULT 0,"
        "sell_price DECIMAL(10,2) NOT NULL DEFAULT 0"
        ") " + tail
    )
    _run(
        "CREATE TABLE IF NOT EXISTS tyre_stock_log ("
        "id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
        "ts DATETIME NOT NULL,"
        "kind VARCHAR(10) NOT NULL,"
        "item VARCHAR(150) NOT NULL,"
        "qty INT NOT NULL,"
        "unit_price DECIMAL(10,2) NOT NULL DEFAULT 0,"
        "total DECIMAL(12,2) NOT NULL DEFAULT 0,"
        "effect VARCHAR(200) NOT NULL,"
        "INDEX idx_stock_ts (ts)"
        ") " + tail
    )
    _run(
        "CREATE TABLE IF NOT EXISTS tyre_work_log ("
        "id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
        "ts DATETIME NOT NULL,"
        "descr VARCHAR(300) NOT NULL,"
        "amount DECIMAL(10,2) NOT NULL,"
        "INDEX idx_work_ts (ts)"
        ") " + tail
    )

    row = _run("SELECT user_key FROM tyre_users WHERE user_key = %s", (USER_KEY,), fetch="one")
    if row is None:
        env_pw = os.environ.get("EID_INITIAL_PASSWORD")
        pw = env_pw or new_temp_password()
        _run(
            "INSERT IGNORE INTO tyre_users (user_key, display_name, password_hash, must_change) "
            "VALUES (%s, %s, %s, 1)",
            (USER_KEY, USER_NAME, generate_password_hash(pw)),
        )
        if not env_pw:
            print("=== كلمة مرور عيد المؤقتة: " + pw + " ===", flush=True)

    # إعادة تعيين كلمة المرور عند النسيان: ضع EID_RESET_PASSWORD بقيمة جديدة مرة واحدة.
    # يُطبَّق مرة واحدة لكل قيمة (لا يتكرر عند إعادة تشغيل السيرفر).
    reset_pw = os.environ.get("EID_RESET_PASSWORD")
    if reset_pw:
        marker = hashlib.sha256(reset_pw.encode()).hexdigest()
        row = _run("SELECT reset_marker FROM tyre_users WHERE user_key = %s", (USER_KEY,), fetch="one")
        if row is not None and row["reset_marker"] != marker:
            _run(
                "UPDATE tyre_users SET password_hash = %s, must_change = 1, reset_marker = %s "
                "WHERE user_key = %s",
                (generate_password_hash(reset_pw), marker, USER_KEY),
            )


# --- دوال الوصول للبيانات (كل استعلامات SQL هنا) ---
def db_get_user(user_key):
    return _run(
        "SELECT user_key, display_name, password_hash, must_change FROM tyre_users WHERE user_key = %s",
        (user_key,), fetch="one",
    )


def db_set_password(user_key, new_hash):
    _run(
        "UPDATE tyre_users SET password_hash = %s, must_change = 0 WHERE user_key = %s",
        (new_hash, user_key),
    )


def db_list_items():
    return _run("SELECT name, qty, buy_price, sell_price FROM tyre_items ORDER BY name", fetch="all")


def db_upsert_item(name, qty, buy_price, sell_price):
    _run(
        "INSERT INTO tyre_items (name, qty, buy_price, sell_price) VALUES (%s, %s, %s, %s) "
        "ON DUPLICATE KEY UPDATE qty = VALUES(qty), buy_price = VALUES(buy_price), "
        "sell_price = VALUES(sell_price)",
        (name, qty, buy_price, sell_price),
    )


def db_delete_item(name):
    return _run("DELETE FROM tyre_items WHERE name = %s", (name,))


def db_transaction(kind, name, qty, now):
    """بيع أو شراء. يرجع (نجح؟، رسالة). العملية كلها ذرّية: المخزون والسجل معاً."""
    def work(cur):
        if kind == 'sell':
            cur.execute("SELECT qty, sell_price FROM tyre_items WHERE name = %s FOR UPDATE", (name,))
            row = cur.fetchone()
            if row is None:
                return False, 'الرجاء اختيار صنف صحيح من المخزون.'
            if row['qty'] < qty:
                return False, 'الكمية المباعة أكبر من المتوفر بالمخزون الحالي!'
            cur.execute("UPDATE tyre_items SET qty = qty - %s WHERE name = %s", (qty, name))
            unit = row['sell_price']
            effect = 'تم خصم %d قطعة تلقائياً' % qty
        else:
            cur.execute(
                "INSERT INTO tyre_items (name, qty, buy_price, sell_price) VALUES (%s, %s, 0, 0) "
                "ON DUPLICATE KEY UPDATE qty = qty + VALUES(qty)",
                (name, qty),
            )
            cur.execute("SELECT buy_price FROM tyre_items WHERE name = %s", (name,))
            unit = cur.fetchone()['buy_price']
            effect = 'تم إضافة %d قطعة تلقائياً' % qty
        total = (Decimal(unit) * qty).quantize(Decimal('0.01'))
        cur.execute(
            "INSERT INTO tyre_stock_log (ts, kind, item, qty, unit_price, total, effect) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (now, kind, name, qty, unit, total, effect),
        )
        return True, 'تمت الحركة وتحديث المخزون تلقائياً بنجاح!'
    return _tx(work)


def db_add_work(now, descr, amount):
    _run("INSERT INTO tyre_work_log (ts, descr, amount) VALUES (%s, %s, %s)", (now, descr, amount))


def db_delete_work(work_id):
    return _run("DELETE FROM tyre_work_log WHERE id = %s", (work_id,))


def db_day_data(start, end):
    """سجلات يوم واحد ومجاميعه (start <= الوقت < end)."""
    def work(cur):
        out = {}
        cur.execute(
            "SELECT id, ts, descr, amount FROM tyre_work_log WHERE ts >= %s AND ts < %s "
            "ORDER BY ts DESC, id DESC", (start, end))
        out['work'] = cur.fetchall()
        cur.execute(
            "SELECT id, ts, kind, item, qty, unit_price, total, effect FROM tyre_stock_log "
            "WHERE ts >= %s AND ts < %s ORDER BY ts DESC, id DESC", (start, end))
        out['stock'] = cur.fetchall()
        cur.execute(
            "SELECT COALESCE(SUM(amount), 0) AS s FROM tyre_work_log WHERE ts >= %s AND ts < %s",
            (start, end))
        out['work_total'] = cur.fetchone()['s']
        cur.execute(
            "SELECT COALESCE(SUM(total), 0) AS s FROM tyre_stock_log "
            "WHERE kind = 'sell' AND ts >= %s AND ts < %s", (start, end))
        out['sales_total'] = cur.fetchone()['s']
        cur.execute(
            "SELECT COALESCE(SUM(total), 0) AS s FROM tyre_stock_log "
            "WHERE kind = 'buy' AND ts >= %s AND ts < %s", (start, end))
        out['buys_total'] = cur.fetchone()['s']
        return out
    return _tx(work)


def db_stats():
    return _run(
        "SELECT COUNT(*) AS n, COALESCE(SUM(qty * buy_price), 0) AS cost, "
        "COALESCE(SUM(qty * sell_price), 0) AS value FROM tyre_items",
        fetch="one",
    )


# ----------------------------------------------------------------------
# الأمان
# ----------------------------------------------------------------------
FAILS = {}


def too_many(ident):
    now = time.time()
    recent = [t for t in FAILS.get(ident, []) if now - t < FAIL_WINDOW]
    FAILS[ident] = recent
    return len(recent) >= MAX_FAILS


def record_fail(ident):
    if len(FAILS) > 5000:
        FAILS.clear()
    FAILS.setdefault(ident, []).append(time.time())


def clear_fails(ident):
    FAILS.pop(ident, None)


def csrf_token():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_hex(16)
    return session['csrf']


app.jinja_env.globals['csrf_token'] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == 'POST':
        sent = (request.form.get('csrf') or '').encode()
        expected = (session.get('csrf') or '').encode()
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400)


@app.after_request
def add_security_headers(response):
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    if ON_RENDER:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return response


@app.errorhandler(400)
def bad_request(_e):
    return 'طلب غير صالح. أعد تحميل الصفحة وحاول مرة أخرى.', 400


def client_ip():
    return (request.remote_addr or 'unknown')[:45]


def flash_msg(text, ok=True):
    session['flash'] = ['ok' if ok else 'error', text]


def current_user():
    key = session.get('user')
    if not key:
        return None
    user = db_get_user(key)
    if user is None:
        session.clear()
    return user


# ----------------------------------------------------------------------
# قراءة الأرقام (تقبل الأرقام العربية والفاصلة العربية)
# ----------------------------------------------------------------------
_DIGITS = str.maketrans('٠١٢٣٤٥٦٧٨٩٫،,', '0123456789...')


def parse_decimal(raw, min_value=Decimal('0'), max_value=MAX_MONEY):
    text = (raw or '').strip().translate(_DIGITS)
    try:
        value = Decimal(text)
    except (InvalidOperation, ValueError):
        return None
    if not value.is_finite():
        return None
    value = value.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    if value < min_value or value > max_value:
        return None
    return value


def parse_int(raw, min_value=0, max_value=MAX_QTY):
    text = (raw or '').strip().translate(_DIGITS)
    if not text.isdigit():
        return None
    value = int(text)
    if value < min_value or value > max_value:
        return None
    return value


def clean_text(raw, max_len):
    text = ' '.join((raw or '').split())
    if not text or len(text) > max_len:
        return None
    return text


# ----------------------------------------------------------------------
# التصميم
# ----------------------------------------------------------------------
BASE_CSS = '''
:root { --bg:#f1f5f9; --ink:#0f172a; --muted:#64748b; --line:#e2e8f0; --brand:#2563eb;
        --ok:#16a34a; --warn:#f59e0b; --bad:#dc2626; --work:#ea580c; }
* { box-sizing: border-box; }
body { font-family: Tahoma, Arial, sans-serif; background: var(--bg); color: var(--ink); margin: 0; padding: 14px; }
.container { max-width: 1000px; margin: auto; }
.top { background: linear-gradient(135deg, #1e3a8a, #2563eb); color: #fff; border-radius: 16px; padding: 16px 18px;
       display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 14px; }
.top h1 { margin: 0; font-size: 20px; }
.top small { opacity: .9; }
.card { background: #fff; border: 1px solid var(--line); border-radius: 16px; padding: 16px; margin-bottom: 14px;
        box-shadow: 0 2px 10px rgba(15,23,42,.05); }
.card h2, .card h3 { margin: 0 0 12px; font-size: 17px; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 14px; }
.stat { background: #fff; border: 1px solid var(--line); border-radius: 14px; padding: 12px; text-align: center; }
.stat b { display: block; font-size: 20px; margin-top: 4px; }
.stat.work b { color: var(--work); } .stat.sell b { color: var(--ok); } .stat.buy b { color: var(--bad); }
label { display: block; font-size: 14px; color: var(--muted); margin-bottom: 2px; }
input, select { width: 100%; padding: 11px; margin: 4px 0 12px; border: 1px solid #cbd5e1; border-radius: 10px;
                font-size: 16px; font-family: inherit; background: #fff; }
.btn { display: inline-block; background: var(--brand); color: #fff; padding: 11px 16px; border: 0; border-radius: 10px;
       cursor: pointer; font-size: 16px; font-family: inherit; text-align: center; text-decoration: none; }
.btn.full { width: 100%; }
.btn.ok { background: var(--ok); } .btn.warn { background: var(--warn); color: #1f2937; }
.btn.bad { background: var(--bad); } .btn.work { background: var(--work); }
.btn.small { padding: 6px 10px; font-size: 13px; border-radius: 8px; }
.btn.light { background: rgba(255,255,255,.2); }
.notice { padding: 11px 14px; border-radius: 12px; margin-bottom: 14px; font-weight: bold; text-align: center; }
.notice.ok { background: #dcfce7; color: #166534; } .notice.err { background: #fee2e2; color: #991b1b; }
.notice.info { background: #fef9c3; color: #854d0e; }
.tablewrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; min-width: 480px; font-size: 14px; }
th { background: #1e293b; color: #fff; padding: 9px; }
td { border-bottom: 1px solid var(--line); padding: 9px; text-align: center; }
.sell-t { color: var(--ok); font-weight: bold; } .buy-t { color: var(--bad); font-weight: bold; }
.muted { color: var(--muted); }
.row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.auth { max-width: 380px; margin: 40px auto; }
.footer { text-align: center; color: var(--muted); font-size: 12px; margin: 20px 0; }
@media (max-width: 480px) { .row2 { grid-template-columns: 1fr; } }
'''

LOGIN_HTML = '''
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#1e3a8a">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="apple-touch-icon" href="/icons/icon-192.png">
<title>تسجيل الدخول - نظام إدارة مخزون البناشر</title>
<style>{{ css|safe }}</style></head>
<body>
<div class="container">
  <div class="card auth">
    <h2 style="text-align:center">🛞 نظام إدارة مخزون البناشر</h2>
    {% if error %}<div class="notice err">{{ error }}</div>{% endif %}
    <form method="POST">
      <input type="hidden" name="csrf" value="{{ csrf_token() }}">
      <label>اسم المستخدم</label>
      <input type="text" name="username" required autocomplete="username" autocapitalize="none" placeholder="عيد">
      <label>كلمة السر</label>
      <input type="password" name="password" required autocomplete="current-password">
      <button type="submit" class="btn full">دخول</button>
    </form>
  </div>
</div>
<script>if ('serviceWorker' in navigator) { window.addEventListener('load', function () { navigator.serviceWorker.register('/sw.js'); }); }</script>
</body></html>
'''

CHANGE_PW_HTML = '''
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#1e3a8a">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="apple-touch-icon" href="/icons/icon-192.png">
<title>تغيير كلمة السر</title>
<style>{{ css|safe }}</style></head>
<body>
<div class="container">
  <div class="card auth">
    <h2 style="text-align:center">🔐 تغيير كلمة السر</h2>
    {% if forced %}<div class="notice info">يجب تغيير كلمة السر المؤقتة قبل المتابعة.</div>{% endif %}
    {% if error %}<div class="notice err">{{ error }}</div>{% endif %}
    <form method="POST">
      <input type="hidden" name="csrf" value="{{ csrf_token() }}">
      <label>كلمة السر الحالية</label>
      <input type="password" name="old_password" required autocomplete="current-password">
      <label>كلمة السر الجديدة (8 أحرف على الأقل)</label>
      <input type="password" name="new_password" required minlength="8" autocomplete="new-password">
      <label>تأكيد كلمة السر الجديدة</label>
      <input type="password" name="confirm_password" required minlength="8" autocomplete="new-password">
      <button type="submit" class="btn ok full">حفظ</button>
    </form>
    <p style="text-align:center">
      {% if not forced %}<a href="{{ url_for('index') }}">رجوع</a> | {% endif %}
      <a href="{{ url_for('logout') }}">تسجيل خروج</a>
    </p>
  </div>
</div>
<script>if ('serviceWorker' in navigator) { window.addEventListener('load', function () { navigator.serviceWorker.register('/sw.js'); }); }</script>
</body></html>
'''

MAIN_HTML = '''
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#1e3a8a">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="apple-touch-icon" href="/icons/icon-192.png">
<title>نظام إدارة مخزون البناشر</title>
<style>{{ css|safe }}</style></head>
<body>
<div class="container">

  <div class="top">
    <div>
      <h1>🛞 نظام إدارة مخزون البناشر</h1>
      <small>المستخدم: <b>{{ user_name }}</b></small>
    </div>
    <div style="display:flex; gap:8px; flex-wrap:wrap">
      <a href="{{ url_for('change_password') }}" class="btn light small">🔐 كلمة السر</a>
      <a href="{{ url_for('logout') }}" class="btn light small">تسجيل خروج</a>
    </div>
  </div>

  {% if flash %}<div class="notice {{ 'err' if flash[0] == 'error' else 'ok' }}">{{ flash[1] }}</div>{% endif %}

  <div class="card">
    <form method="GET" style="display:flex; gap:8px; align-items:end; flex-wrap:wrap">
      <div style="flex:1; min-width:150px">
        <label>عرض سجلات يوم:</label>
        <input type="date" name="d" value="{{ day_str }}" style="margin-bottom:0">
      </div>
      <button type="submit" class="btn">عرض</button>
      {% if not is_today %}<a href="{{ url_for('index') }}" class="btn ok">اليوم</a>{% endif %}
    </form>
    <p class="muted" style="margin:10px 0 0">
      {% if is_today %}سجلات اليوم ({{ day_str }}){% else %}أنت تعرض سجلات يوم {{ day_str }}{% endif %}
    </p>
  </div>

  <div class="stats">
    <div class="stat work">شغل اليد<b>{{ day.work_total | money }}</b><span class="muted">شيكل</span></div>
    <div class="stat sell">مبيعات الأصناف<b>{{ day.sales_total | money }}</b><span class="muted">شيكل</span></div>
    <div class="stat buy">مشتريات الأصناف<b>{{ day.buys_total | money }}</b><span class="muted">شيكل</span></div>
    <div class="stat">قيمة المخزون (بسعر البيع)<b>{{ stats.value | money }}</b><span class="muted">{{ stats.n }} صنف</span></div>
  </div>

  <div class="card" style="border-right:5px solid var(--work)">
    <h3>💵 تسجيل الشغل اليومي (أجرة اليد / الخدمات)</h3>
    <form method="POST" action="{{ url_for('add_work') }}">
      <input type="hidden" name="csrf" value="{{ csrf_token() }}">
      <label>تفاصيل الشغل (مثلاً: تركيب كوشوك، ترصيص، بنشر...)</label>
      <input type="text" name="work_desc" required maxlength="300" placeholder="اكتب وصف الشغل هنا...">
      <label>المبلغ (بالشيكل)</label>
      <input type="number" step="0.01" min="0.01" name="work_amount" required placeholder="0.00" inputmode="decimal">
      <button type="submit" class="btn work full">تسجيل شغل اليوم</button>
    </form>
  </div>

  <div class="card" style="border-right:5px solid var(--brand)">
    <h3>⚡ حركة المخزون (بيع / شراء)</h3>
    <form method="POST" action="{{ url_for('daily_transaction') }}">
      <input type="hidden" name="csrf" value="{{ csrf_token() }}">
      <label>نوع العملية</label>
      <select name="action_type">
        <option value="sell">📉 بيع (ينقص المخزون تلقائياً)</option>
        <option value="buy">📈 شراء / توريد (يزيد المخزون تلقائياً)</option>
      </select>
      <label>اختر الصنف المتوفر</label>
      <select name="item_name">
        <option value="">--- اختر صنفاً من المخزون ---</option>
        {% for it in items %}<option value="{{ it.name }}">{{ it.name }} (المتوفر: {{ it.qty }})</option>{% endfor %}
      </select>
      <label>أو اكتب اسم صنف جديد (عند التوريد/الشراء فقط)</label>
      <input type="text" name="new_item_name" maxlength="150" placeholder="اكتب اسم الصنف الجديد هنا...">
      <label>الكمية</label>
      <input type="number" name="quantity" min="1" required placeholder="الكمية" inputmode="numeric">
      <button type="submit" class="btn full">تنفيذ وتحديث المخزون تلقائياً</button>
    </form>
  </div>

  <div class="card" style="border-right:5px solid var(--ok)" id="item-form">
    <h3>➕ إضافة أو تعديل صنف بالمخزون</h3>
    <form method="POST" action="{{ url_for('save_item') }}">
      <input type="hidden" name="csrf" value="{{ csrf_token() }}">
      <label>اسم الصنف</label>
      <input type="text" name="item_name" id="si_name" required maxlength="150" placeholder="اسم الصنف">
      <label>الكمية الكلية</label>
      <input type="number" name="qty" id="si_qty" required min="0" placeholder="الكمية" inputmode="numeric">
      <div class="row2">
        <div><label>سعر الشراء</label>
          <input type="number" step="0.01" min="0" name="buy_price" id="si_buy" required placeholder="0.00" inputmode="decimal"></div>
        <div><label>سعر البيع</label>
          <input type="number" step="0.01" min="0" name="sell_price" id="si_sell" required placeholder="0.00" inputmode="decimal"></div>
      </div>
      <button type="submit" class="btn ok full">حفظ أو تعديل الصنف</button>
    </form>
  </div>

  <div class="card">
    <h2>📋 سجل الشغل ({{ day_str }})</h2>
    <div class="tablewrap">
    <table>
      <tr><th>الوقت</th><th>تفاصيل العمل</th><th>المبلغ</th><th></th></tr>
      {% for w in day.work %}
      <tr>
        <td>{{ w.ts | hm }}</td>
        <td>{{ w.descr }}</td>
        <td><b style="color:var(--ok)">{{ w.amount | money }} شيكل</b></td>
        <td>
          <form method="POST" action="{{ url_for('delete_work') }}" style="margin:0"
                onsubmit="return confirm('متأكد بدك تحذف هذا السجل؟')">
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            <input type="hidden" name="work_id" value="{{ w.id }}">
            <button type="submit" class="btn bad small">حذف</button>
          </form>
        </td>
      </tr>
      {% else %}
      <tr><td colspan="4" class="muted">لا يوجد شغل مسجّل في هذا اليوم.</td></tr>
      {% endfor %}
    </table>
    </div>
  </div>

  <div class="card">
    <h2>📦 المخزون الكلي للمحل</h2>
    <div class="tablewrap">
    <table>
      <tr><th>الصنف</th><th>الكمية</th><th>شراء</th><th>بيع</th><th>إجراءات</th></tr>
      {% for it in items %}
      <tr>
        <td><b>{{ it.name }}</b></td>
        <td>{{ it.qty }}</td>
        <td>{{ it.buy_price | money }}</td>
        <td>{{ it.sell_price | money }}</td>
        <td>
          <div style="display:flex; gap:6px; justify-content:center">
            <button type="button" class="btn warn small"
                    data-name="{{ it.name }}" data-qty="{{ it.qty }}"
                    data-buy="{{ it.buy_price }}" data-sell="{{ it.sell_price }}"
                    onclick="editItem(this)">تعديل</button>
            <form method="POST" action="{{ url_for('delete_item') }}" style="margin:0"
                  onsubmit="return confirm('متأكد بدك تحذف هذا الصنف؟')">
              <input type="hidden" name="csrf" value="{{ csrf_token() }}">
              <input type="hidden" name="item_name" value="{{ it.name }}">
              <button type="submit" class="btn bad small">حذف</button>
            </form>
          </div>
        </td>
      </tr>
      {% else %}
      <tr><td colspan="5" class="muted">لا توجد أصناف مخزنة حالياً. ابدأ بإضافة أصناف جديدة.</td></tr>
      {% endfor %}
    </table>
    </div>
  </div>

  <div class="card">
    <h2>📊 سجل حركات المخزون ({{ day_str }})</h2>
    <div class="tablewrap">
    <table>
      <tr><th>الوقت</th><th>الحركة</th><th>الصنف</th><th>الكمية</th><th>المبلغ</th><th>التأثير</th></tr>
      {% for s in day.stock %}
      <tr>
        <td>{{ s.ts | hm }}</td>
        <td>{% if s.kind == 'sell' %}<span class="sell-t">بيع</span>{% else %}<span class="buy-t">شراء</span>{% endif %}</td>
        <td>{{ s.item }}</td>
        <td>{{ s.qty }}</td>
        <td>{{ s.total | money }}</td>
        <td>{{ s.effect }}</td>
      </tr>
      {% else %}
      <tr><td colspan="6" class="muted">لا توجد حركات مخزون في هذا اليوم.</td></tr>
      {% endfor %}
    </table>
    </div>
  </div>

  <div class="footer">Inventory management system by Abu Joud</div>
</div>

<script>
  function editItem(btn) {
    document.getElementById('si_name').value = btn.dataset.name;
    document.getElementById('si_qty').value = btn.dataset.qty;
    document.getElementById('si_buy').value = btn.dataset.buy;
    document.getElementById('si_sell').value = btn.dataset.sell;
    document.getElementById('item-form').scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
</script>
<script>if ('serviceWorker' in navigator) { window.addEventListener('load', function () { navigator.serviceWorker.register('/sw.js'); }); }</script>
</body></html>
'''


@app.template_filter('money')
def money_filter(value):
    try:
        return '{:,.2f}'.format(Decimal(value))
    except Exception:
        return '0.00'


@app.template_filter('hm')
def time_filter(value):
    try:
        return value.strftime('%H:%M')
    except Exception:
        return ''



# ----------------------------------------------------------------------
# تثبيت الموقع كتطبيق (PWA)
# ----------------------------------------------------------------------
_ICON_192 = """
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
ZMycmTyfTtDQ2DubfIPRfwCkf73ymruyudogkt3QzNX6JgkoCaoesZ0XYcyIXhCsiuFlAAbU6uwuaqQ/b0VcrJHj0TF4RwAB
RAgqls7EBflIbNwjlSJaX77e6NmEPGM3ks21oRORQAwKI+d17JbDqvysWvyy8i8CUiAWIK7yGOlpGzt27KhWq7VaLY7jHkoU
fZimmUwmU6nU7OxsEKzpi4UEFID0QQl0d+PgO0j+vog4KD2irfeeWtdbzVxtYmE3KHO12wgCAER5AATzD2LmLlV+RhWfVt55
UGLZ8agAlM73SCaTfX19fX19c3NzFy9ebDmRtKVEWde7o0sfR0dHBwcHAaBer3uet7w+AURQHHgNkGFiL/a9meTvA5YA4aGs
X4lO3FTM1ViT3TTM1epicAlGCLwOSDD/IOZer2rHVelbqnoEeAWQATEBCCBJJJOawqrVajd8ZFlWOp3WaRj1+vrtUavVaj6f
B4BEMgnzCwAEQID0l7pe5u8iffdj6jYg1rK6Q24Q9FyNJs5uNuZqd5Fat/AACaZehelXQzCrKt9T1ReVf1HEZdt0UgkXkPCY
1+teywnRzRJFCOE4ztjYGCJOTU1Vq9UOEktPUq7XPT2zMpVwbSbDsEyMJCYPYOa1JHs32CMACoQPIgak0KJ08GZirsaa7CZk
rjUXCU3NPwBAeAAIZh8OvhP73wbhFJRfMnFSAhgQVmuFKKwyZqvmkedLyFg9wUnHGVr5uHHF1SpFUEZBxa/OZXN9HC2z/84Y
x1n2NWDvXAqF8rq24FtMB7gJmatJB7pZmav95mqFVMXAI0ACzk7q7glkfEqUEvEsVydI0oZ4DuIqqHjZ6UIBKSAu9z3WBhG5
8kMtM5YUcwlKghIAApQEUIAGGGliT8zDoaI8WIdhNdLH0AAVgYyBVwFxhWvnxkBPT3xI7OZmrk4bgUu8JiNQISBRNF1ROcwc
ZhkOcUnFsxBMqWAG4gUVFyEug+IgfAAAKSGOUDIGPgKirENcATCX4EUdIAYYGTTyYPajPQz2TrSGiJn3gSklCQqUISh/SctB
7OjPvimZq4Uf6CZmrnUuZvntV5wC1zFQMDNo9UPq1QgAioOMgNdAxSoqAALwMo3Koe1MqjQorGfqlFbRzCLLAgKafYAGsDQQ
C5Au9YpQMagIISRAdJx36b+2Tk5cV+Za7Qd6JTBXF1BWjTUVB8WXdB5NUkYWANEe0boUBRIpNacrUxOEJnXZtQIAUAJAgRIg
A1Bq2RbUMWDS5nrgFcZcK/xAryzm6nLNNcNi9WA2GTc0acSlbk1KrmLGpgaouGKdrZsseaMx1xUd6JXLXBvd3BZFemoja7ae
ifwKZa7G32TLZM+Nw1zXQrBv0UzkG5a5GmuS7zPmuoboeUUzV+M62fc9c20Ber4PmKu7ufHbzLXNXOutSbaZa5u5ruY62TZz
bTPX1Vwn2Waubea6mjXJNnNtM9fVXCfbZq5t5trsdS5R2DZzbTPX5ta84oneZq5t5trkprFt5tpmrquZQkm2mWubuTaNHliR
L7fNXNvMtbFNa6awbebaZq4Nyp72fqBt5tpmri5kT5MOtM1c28y1mU1bSufYZq5t5towc60NZWwz1zZzbYC51joSt5lrm7k2
ow2zbebaZq5NMFfjRLLNXNvMtQnmWpvSus1c28y1GW2YbTPXNnNtgrk6+IG2mWubudZnrpZ+oO9b2bPFT3rL5lT09Dp7ldL6
/chcNxt6YCvk2SZP/P8Bm+KqB7crBYcAAAAASUVORK5CYII=
"""
_ICON_512 = """
iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAIAAAB7GkOtAAC3N0lEQVR42uz9d3yk13nYjz7POW+djrbA7gLbuIVFJJfLrkJJ
FCnKVrFkS3Kc2I7jxHGuY3/iG5e4xJIl/2zlp8S/a8d2HPsmtmwnuYkli+oSxaIu1l0uu5ZcbsVigUWb/tZzzv3jALODwcxg
ALwzGMyc96OywGBm3nLO9+nPg3ve+ElY48BWX8XNvb3+r3ET5wYA2PRPcH3Xjpt7e51XNnh1WP3/GNHV1f4CN7UwELd0XTX4
A9zKq8Me2TXr/HyM6Oo2vWtgQ7sGO7prIrq6ltcV2dwuhU3vUtjcLt3kOobNreNNfjBG8CkY0dWt+6Nwc6sGI/mejdK/Xd/a
E29XN6eP7q2mdH+l+yvdX+n+SvfvN91/TQtA6f5K91e6v9JP1c3p5XtLOiltOqSjbbEWs6aatvGrw5bov049Ajf39o5qMRv6
fIzo6tZW/9fcDNid62o7GM0RmZUbVP83ua6612gmiv6K/or+iv6K/n1I/7oCQNFf0V/RX9Ff0b/36Q+ARNFf0V/RX9Ff0b8P
6V9jASj6K/or+iv6K/r3C/2rBYCiv6K/or+iv6J/H9G/IgAU/RX9Ff0V/RX9+4v+UgAo+iv6K/or+iv69x39YR2tIBT9Ff0V
/RX9Ff17iP5rCgBFf0V/RX9Ff0X/3qQ/YCutIBT9Ff0V/RX9Ff17jv6wdisIRX9Ff0V/RX9F/16kP6zRCkLRX9Ff0V/RX9G/
R+kP9dpBK/or+iv6K/or+vc8/XG1BaDor+iv6K/or+jf+7p/jQXQ3VM4FP0V/RX9Ff0V/aPeNWTdC17RX9Ff0V/RX9F/+9Nf
WgBK91f0V/RX9Ff07zv6r7QAFP0V/RX9Ff0V/fuG/lUCQNFf0V/RX9Ff0b+f6L8sABT9Ff0V/RX9Ff37jP4AQBT9Ff0V/RX9
Ff37kP6w2aHwiv6K/or+iv6K/tuT/rCpofCK/or+iv6K/or+25b+mxgKr+iv6K/or+iv6L+d6Q8bHAqv6K/or+iv6K/ov83p
DxsZCq/or+iv6K/or+i//ekP6x4Kr+iv6K/or+iv6N8T9If1DYVX9Ff0V/RX9Ff07xX6wzqGwiv6K/or+iv6K/r3EP2h1aHw
iv6K/or+iv6K/r1F/+YCQNFf0V/RX9Ff0b9n6Q9rD4VX9Ff0V/RX9Ff070X6wzpaQSj6K/or+iv6K/r3EP2h2VB4RX9Ff0V/
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
1J/6U3/qn3X9xwUA6k/9qT/1p/4LoP9IAKD+1J/6U3/qvxj6Y7AO4BzvUupP/ak/9af+M68/TrAVBPWn/tSf+lP/DOkPIGDb
n/pTf+pP/RdQ/3TxUupP/ak/9af+C6Q/UnsBHftZqT/1p/7Un/pnR38cMQZA/ak/9af+1D/j+uOoovDUn/pTf+pP/bOt/5Q9
AOpP/ak/9af+WdN/mgBA/ak/9af+1D+D+h8bAKg/9af+1J/6Z1P/yQGA+lN/6k/9qX9m9Z8QAKg/9af+1J/6Z1l/nGYrCOpP
/ak/9af+868/RorCU3/qT/2pP/VfBP1ltAdA/ak/9af+1D/7bf+hHsAZfaT+1J/6U3/qPy/6y1EpIOpP/ak/9af+WddfegGA
bX/qT/2pP/VfrLa/P45bCUz9qT/1p/7UP2P6yzQBgPpTf+pP/al/RvWfGACoP/Wn/tSf+mdX/6MDAPWn/tSf+lP/TOt/RACg
/tSf+lN/6p91/ccFAOpP/ak/9af+C6D/SFF46k/9qT/1p/6LoT8GC8HkPC4U6k/9qT/1p/5zon86BUT9qT/1p/7Uf4H0BxCw
7U/9qT/1p/4LqL/vAVB/6k/9qT/1Xzj9cdai8NSf+lN/6k/951N/nKkoPPWn/tSf+lP/udUfpy8KT/2pP/Wn/tR/nvXHKYvC
U3/qT/2pP/Wfc/1xmqLw1J/6U3/qT/3nX3+cuCg89af+1J/6U/8s6H/SovDUn/pTf+pP/TPR9h/qAZynj9Sf+lN/6k/9Z1j/
4a0gqD/1p/7Un/ovkP6Yqig89af+1J/6U//M6Y+TrQSm/tSf+lN/6p8V/XGClcDUn/pTf+pP/TOkP8ZNA6X+1J/6U3/qn3X9
ZVIPgPpTf+pP/al/Ztv+E1JA1J/6U3/qT/2zq78cGQCoP/Wn/tSf+mdf/5Gi8NSf+lN/6k/9F0P/oR4A9af+1J/6U/9F0R/j
i8JTf+pP/ak/9c+6/kkAoP7Un/pTf+q/WPpjuCg89af+1J/6U//F0B+DhWByHhcK9af+1J/6U/850R/nVhSe+lN/6k/9qf9c
6Q8gYNuf+lN/6k/9F1B/nENReOpP/ak/9af+c6g/zloUnvpTf+pP/an/fOqPMxWFp/7Un/pTf+o/r/qfpSg89af+1J/6U/+5
bfsP9QDO+GbUn/pTf+pP/edF/1MXhaf+1J/6U3/qP//648RF4ak/9af+1J/6Z0J/nKwoPPWn/tSf+lP/rOiP06wEpv7Un/pT
f+o///pPDgDUn/pTf+pP/TOrP8atA7iPb3ZOF/Gxd6lM/01wInmmv4zknG7Ri76Ip379+7yDiJzuwpBZvkVnvM102gtDpry2
7utdM+Ntpgu6a07x4uZU73c2vu+v/qf9JnJO3+6s1zHOdh3fV/1xtusYU17Hp/yScoaTc8Zzi/M7t3P768JzO4e//v/dRoB+
sYWe9wAAAABJRU5ErkJggg==
"""
_ICON_MASKABLE_512 = """
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
"""

ICONS = {
    'icon-192.png': base64.b64decode(''.join(_ICON_192.split())),
    'icon-512.png': base64.b64decode(''.join(_ICON_512.split())),
    'icon-maskable-512.png': base64.b64decode(''.join(_ICON_MASKABLE_512.split())),
}

SW_JS = """
const CACHE = 'tyre-shop-offline-v1';
const OFFLINE_URL = '/offline';
self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.add(OFFLINE_URL)));
  self.skipWaiting();
});
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
  );
  self.clients.claim();
});
self.addEventListener('fetch', (event) => {
  if (event.request.mode === 'navigate') {
    event.respondWith(fetch(event.request).catch(() => caches.match(OFFLINE_URL)));
  }
});
"""

OFFLINE_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>لا يوجد اتصال</title>
<style>
  body { font-family: Tahoma, Arial, sans-serif; background: #f1f5f9; display: flex; justify-content: center;
         align-items: center; min-height: 100vh; margin: 0; text-align: center; color: #0f172a; }
  .box { background: #fff; padding: 30px; border-radius: 16px; max-width: 340px; box-shadow: 0 4px 20px rgba(0,0,0,.08); }
  button { background: #2563eb; color: #fff; border: 0; border-radius: 10px; padding: 10px 20px; font-size: 16px; cursor: pointer; }
</style>
</head>
<body><div class="box">
  <h2>📡 لا يوجد اتصال</h2>
  <p>تعذّر الوصول للموقع. تأكد من الإنترنت وحاول مرة أخرى.<br>
  (إذا كان الموقع نائماً قد يحتاج حوالي دقيقة ليصحو.)</p>
  <button onclick="location.reload()">إعادة المحاولة</button>
</div></body>
</html>
"""


@app.route('/manifest.webmanifest')
def manifest():
    data = {
        "name": "نظام إدارة مخزون البناشر",
        "short_name": "البناشر",
        "description": "إدارة المخزون وتسجيل الشغل اليومي للبناشر",
        "id": "/",
        "start_url": "/",
        "scope": "/",
        "display": "standalone",
        "lang": "ar",
        "dir": "rtl",
        "background_color": "#f1f5f9",
        "theme_color": "#1e3a8a",
        "icons": [
            {"src": "/icons/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
            {"src": "/icons/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
            {"src": "/icons/icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
        ],
    }
    resp = Response(json.dumps(data, ensure_ascii=False), mimetype='application/manifest+json')
    resp.headers['Cache-Control'] = 'public, max-age=3600'
    return resp


@app.route('/sw.js')
def service_worker():
    resp = Response(SW_JS, mimetype='application/javascript')
    resp.headers['Cache-Control'] = 'no-cache'
    resp.headers['Service-Worker-Allowed'] = '/'
    return resp


@app.route('/icons/<name>')
def pwa_icon(name):
    data = ICONS.get(name)
    if data is None:
        abort(404)
    resp = Response(data, mimetype='image/png')
    resp.headers['Cache-Control'] = 'public, max-age=604800'
    return resp


@app.route('/offline')
def offline():
    return Response(OFFLINE_HTML, mimetype='text/html')


# ----------------------------------------------------------------------
# المسارات
# ----------------------------------------------------------------------
@app.route('/', methods=['GET'])
def index():
    user = current_user()
    if user is None:
        return redirect(url_for('login'))
    if user['must_change']:
        return redirect(url_for('change_password'))

    today = local_now().date()
    day_str = (request.args.get('d') or '').strip()
    try:
        day = datetime.strptime(day_str, '%Y-%m-%d').date() if day_str else today
    except ValueError:
        day = today
    start = datetime(day.year, day.month, day.day)
    end = start + timedelta(days=1)

    return render_template_string(
        MAIN_HTML,
        css=BASE_CSS, user_name=user['display_name'], flash=session.pop('flash', None),
        items=db_list_items(), day=db_day_data(start, end), stats=db_stats(),
        day_str=day.isoformat(), is_today=(day == today),
    )


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user() is not None:
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        raw_name = (request.form.get('username') or '').strip().lower()[:60]
        password = (request.form.get('password') or '')[:128]
        ident = client_ip() + '|' + raw_name
        key = LOGIN_NAMES.get(raw_name)

        if too_many(ident):
            error = 'محاولات كثيرة خاطئة. انتظر 15 دقيقة ثم حاول مرة أخرى.'
        else:
            user = db_get_user(key) if key else None
            ok = False
            if user is not None:
                try:
                    ok = check_password_hash(user['password_hash'], password)
                except ValueError:
                    ok = False
            if ok:
                clear_fails(ident)
                session.clear()
                session.permanent = True
                session['user'] = user['user_key']
                return redirect(url_for('index'))
            record_fail(ident)
            error = 'خطأ في اسم المستخدم أو كلمة السر!'
    return render_template_string(LOGIN_HTML, css=BASE_CSS, error=error)


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    user = current_user()
    if user is None:
        return redirect(url_for('login'))
    error = None
    if request.method == 'POST':
        old_p = (request.form.get('old_password') or '')[:128]
        new_p = (request.form.get('new_password') or '')[:128]
        confirm = (request.form.get('confirm_password') or '')[:128]
        ident = 'chpw|' + user['user_key']
        try:
            old_ok = check_password_hash(user['password_hash'], old_p)
        except ValueError:
            old_ok = False

        if too_many(ident):
            error = 'محاولات كثيرة خاطئة. انتظر 15 دقيقة.'
        elif not old_ok:
            record_fail(ident)
            error = 'كلمة السر الحالية غير صحيحة.'
        elif len(new_p) < MIN_PASSWORD_LEN:
            error = 'كلمة السر الجديدة يجب ألا تقل عن %d أحرف.' % MIN_PASSWORD_LEN
        elif new_p != confirm:
            error = 'تأكيد كلمة السر غير مطابق.'
        elif new_p == old_p:
            error = 'اختر كلمة سر مختلفة عن الحالية.'
        else:
            db_set_password(user['user_key'], generate_password_hash(new_p))
            clear_fails(ident)
            flash_msg('تم تحديث كلمة السر بنجاح!')
            return redirect(url_for('index'))
    return render_template_string(
        CHANGE_PW_HTML, css=BASE_CSS, error=error, forced=bool(user['must_change'])
    )


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


def require_login():
    """يرجع (user, None) أو (None, استجابة تحويل)."""
    user = current_user()
    if user is None:
        return None, redirect(url_for('login'))
    if user['must_change']:
        return None, redirect(url_for('change_password'))
    return user, None


@app.route('/add_work', methods=['POST'])
def add_work():
    user, resp = require_login()
    if resp is not None:
        return resp
    desc = clean_text(request.form.get('work_desc'), 300)
    amount = parse_decimal(request.form.get('work_amount'), min_value=Decimal('0.01'))
    if desc is None:
        flash_msg('اكتب وصف الشغل (حتى 300 حرف).', ok=False)
    elif amount is None:
        flash_msg('الرجاء إدخال مبلغ صحيح أكبر من صفر.', ok=False)
    else:
        db_add_work(local_now(), desc, amount)
        flash_msg('تم تسجيل الشغل اليومي بنجاح!')
    return redirect(url_for('index'))


@app.route('/delete_work', methods=['POST'])
def delete_work():
    user, resp = require_login()
    if resp is not None:
        return resp
    work_id = parse_int(request.form.get('work_id'), min_value=1, max_value=10**15)
    if work_id is not None and db_delete_work(work_id):
        flash_msg('تم حذف سجل الشغل.')
    else:
        flash_msg('السجل غير موجود.', ok=False)
    return redirect(url_for('index'))


@app.route('/save_item', methods=['POST'])
def save_item():
    user, resp = require_login()
    if resp is not None:
        return resp
    name = clean_text(request.form.get('item_name'), 150)
    qty = parse_int(request.form.get('qty'))
    buy = parse_decimal(request.form.get('buy_price'))
    sell = parse_decimal(request.form.get('sell_price'))
    if name is None:
        flash_msg('اكتب اسم الصنف (حتى 150 حرف).', ok=False)
    elif qty is None or buy is None or sell is None:
        flash_msg('الرجاء إدخال أرقام صحيحة للكمية والأسعار.', ok=False)
    else:
        db_upsert_item(name, qty, buy, sell)
        flash_msg('تم حفظ الصنف (%s) بنجاح!' % name)
    return redirect(url_for('index'))


@app.route('/delete_item', methods=['POST'])
def delete_item():
    user, resp = require_login()
    if resp is not None:
        return resp
    name = clean_text(request.form.get('item_name'), 150)
    if name is not None and db_delete_item(name):
        flash_msg('تم حذف الصنف (%s) بنجاح!' % name)
    else:
        flash_msg('الصنف غير موجود.', ok=False)
    return redirect(url_for('index'))


@app.route('/daily_transaction', methods=['POST'])
def daily_transaction():
    user, resp = require_login()
    if resp is not None:
        return resp
    kind = request.form.get('action_type')
    if kind not in ('sell', 'buy'):
        flash_msg('نوع العملية غير صالح.', ok=False)
        return redirect(url_for('index'))

    chosen = clean_text(request.form.get('item_name'), 150)
    new_name = clean_text(request.form.get('new_item_name'), 150)
    # الصنف الجديد مسموح فقط عند الشراء/التوريد
    name = new_name if (new_name and kind == 'buy') else chosen
    qty = parse_int(request.form.get('quantity'), min_value=1)

    if qty is None:
        flash_msg('الكمية يجب أن تكون رقماً صحيحاً أكبر من صفر.', ok=False)
    elif name is None:
        flash_msg('الرجاء اختيار صنف صحيح أو إدخال صنف جديد للتوريد.', ok=False)
    else:
        ok, message = db_transaction(kind, name, qty, local_now())
        flash_msg(message, ok=ok)
    return redirect(url_for('index'))


init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)