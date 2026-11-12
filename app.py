import hashlib
import hmac
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

import pymysql
from pymysql.cursors import DictCursor
from flask import (
    Flask, render_template_string, request, redirect, url_for, session, abort,
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
</body></html>
'''

CHANGE_PW_HTML = '''
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
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
</body></html>
'''

MAIN_HTML = '''
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
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