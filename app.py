from flask import Flask, render_template_string, request, redirect, url_for, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'store_system_secret_key_2026'

# --- إعداد قاعدة البيانات الدائمة (SQLite) ---
def init_db():
    conn = sqlite3.connect('store.db')
    cursor = conn.cursor()
    # جدول المستخدمين
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    # جدول التجار
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS merchants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT,
            details TEXT
        )
    ''')
    # جدول المشتريات
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS purchases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            merchant_name TEXT NOT NULL,
            item TEXT NOT NULL,
            quantity INTEGER,
            price REAL,
            date TEXT
        )
    ''')
    # جدول الدفعات
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            merchant_name TEXT NOT NULL,
            amount REAL,
            date TEXT
        )
    ''')
    
    # إضافة المستخدم الافتراضي eed إذا مش موجود
    cursor.execute("SELECT * FROM users WHERE username = 'eed'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username, password) VALUES ('eed', '000')")
    
    conn.commit()
    conn.close()

init_db()

# --- الواجهة البرمجية (HTML) ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>نظام إدارة التجار والمشتريات</title>
    <style>
        body { font-family: Tahoma, sans-serif; background-color: #f4f7f6; margin: 0; padding: 20px; color: #333; }
        .container { max-width: 950px; margin: auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }
        h1, h2 { color: #2c3e50; text-align: center; }
        .btn { display: inline-block; background: #3498db; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 5px; border: none; cursor: pointer; }
        .btn:hover { background: #2980b9; }
        .btn-danger { background: #e74c3c; }
        .btn-success { background: #27ae60; }
        table { width: 100%%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: center; }
        th { background-color: #2c3e50; color: white; }
        select, input, textarea { width: 100%%; padding: 8px; margin: 5px 0 15px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        .card { background: #ecf0f1; padding: 15px; border-radius: 6px; margin-bottom: 15px; }
        .error { background: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; margin-bottom: 15px; text-align: center; }
        .success-msg { background: #d4edda; color: #155724; padding: 10px; border-radius: 5px; margin-bottom: 15px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📦 نظام إدارة التجار والمشتريات والدفعات</h1>
        
        {% if session.get('user') %}
            <div style="display: flex; justify-content: space-between; align-items: center; background: #e2e8f0; padding: 10px 15px; border-radius: 5px; margin-bottom: 20px;">
                <span>مرحباً بك، <strong>{{ session.get('user') }}</strong></span>
                <a href="/logout" class="btn btn-danger" style="padding: 5px 10px; margin: 0;">تسجيل خروج</a>
            </div>

            {% if error %}<div class="error">{{ error }}</div>{% endif %}
            {% if success %}<div class="success-msg">{{ success }}</div>{% endif %}

            <div class="card" style="background: #eef2f3;">
                <h4>🔐 تغيير كلمة السر الخاصة بك</h4>
                <form method="POST" action="/change_password" style="display: flex; gap: 10px; align-items: flex-end;">
                    <div style="flex: 1; margin: 0;">
                        <input type="password" name="new_password" required placeholder="كلمة السر الجديدة">
                    </div>
                    <button type="submit" class="btn btn-success" style="height: 38px; margin: 0;">تحديث كلمة السر</button>
                </form>
            </div>

            <div class="card">
                <h3>➕ إدخال تاجر جديد</h3>
                <form method="POST" action="/add_merchant">
                    <label>اسم التاجر:</label>
                    <input type="text" name="name" required>
                    <label>رقم الهاتف:</label>
                    <input type="text" name="phone">
                    <label>ملاحظات:</label>
                    <input type="text" name="details">
                    <button type="submit" class="btn">حفظ التاجر</button>
                </form>
            </div>

            <div class="card">
                <h3>🛒 تسجيل مشتريات</h3>
                <form method="POST" action="/add_purchase">
                    <label>اختر التاجر:</label>
                    <select name="merchant_name" required>
                        {% for m in merchants %}
                            <option value="{{ m[1] }}">{{ m[1] }}</option>
                        {% endfor %}
                    </select>
                    <label>اسم المادة / البضاعة:</label>
                    <input type="text" name="item" required>
                    <label>الكمية:</label>
                    <input type="number" name="quantity" required>
                    <label>السعر الإجمالي:</label>
                    <input type="number" step="0.01" name="price" required>
                    <label>التاريخ:</label>
                    <input type="date" name="date" required>
                    <button type="submit" class="btn">حفظ المشتريات</button>
                </form>
            </div>

            <div class="card">
                <h3>💰 تسجيل دفعة مالية</h3>
                <form method="POST" action="/add_payment">
                    <label>اختر التاجر:</label>
                    <select name="merchant_name" required>
                        {% for m in merchants %}
                            <option value="{{ m[1] }}">{{ m[1] }}</option>
                        {% endfor %}
                    </select>
                    <label>مبلغ الدفعة:</label>
                    <input type="number" step="0.01" name="amount" required>
                    <label>التاريخ:</label>
                    <input type="date" name="date" required>
                    <button type="submit" class="btn">حفظ الدفعة</button>
                </form>
            </div>

            <h2>📊 استعلام البيانات المسجلة</h2>
            
            <h3>قائمة التجار</h3>
            <table>
                <tr><th>المعرف</th><th>اسم التاجر</th><th>الهاتف</th><th>الملاحظات</th></tr>
                {% for m in merchants %}
                <tr><td>{{ m[0] }}</td><td>{{ m[1] }}</td><td>{{ m[2] }}</td><td>{{ m[3] }}</td></tr>
                {% else %}
                <tr><td colspan="4">لا يوجد تجار مسجلون.</td></tr>
                {% endfor %}
            </table>

            <h3>سجل المشتريات</h3>
            <table>
                <tr><th>التاجر</th><th>المادة</th><th>الكمية</th><th>السعر</th><th>التاريخ</th></tr>
                {% for p in purchases %}
                <tr><td>{{ p[1] }}</td><td>{{ p[2] }}</td><td>{{ p[3] }}</td><td>{{ p[4] }}</td><td>{{ p[5] }}</td></tr>
                {% else %}
                <tr><td colspan="5">لا توجد مشتريات مسجلة.</td></tr>
                {% endfor %}
            </table>

            <h3>سجل الدفعات المالية</h3>
                <tr><th>التاجر</th><th>المبلغ</th><th>التاريخ</th></tr>
                {% for pay in payments %}
                <tr><td>{{ pay[1] }}</td><td>{{ pay[2] }}</td><td>{{ pay[3] }}</td></tr>
                {% else %}
                <tr><td colspan="3">لا توجد دفعات مسجلة.</td></tr>
                {% endfor %}
            </table>

        {% else %}
            <div class="card" style="max-width: 400px; margin: 40px auto; text-align: center;">
                <h2>تسجيل الدخول للنظام</h2>
                {% if error %}<div class="error">{{ error }}</div>{% endif %}
                <form method="POST" action="/login">
                    <label>اسم المستخدم:</label>
                    <input type="text" name="username" required placeholder="أدخل اسم المستخدم (eed)">
                    <label>كلمة السر:</label>
                    <input type="password" name="password" required placeholder="كلمة السر (000)">
                    <button type="submit" class="btn" style="width: 100%%;">دخول</button>
                </form>
            </div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    conn = sqlite3.connect('store.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM merchants")
    merchants = cursor.fetchall()
    cursor.execute("SELECT * FROM purchases")
    purchases = cursor.fetchall()
    cursor.execute("SELECT * FROM payments")
    payments = cursor.fetchall()
    conn.close()
    
    return render_template_string(HTML_TEMPLATE, 
                                  merchants=merchants, 
                                  purchases=purchases, 
                                  payments=payments,
                                  error=request.args.get('error'),
                                  success=request.args.get('success'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    conn = sqlite3.connect('store.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        session['user'] = username
        return redirect(url_for('index'))
    else:
        return redirect(url_for('index', error='اسم المستخدم أو كلمة السر غير صحيحة!'))

@app.route('/change_password', methods=['POST'])
def change_password():
    if session.get('user'):
        new_pass = request.form.get('new_password')
        if new_pass:
            conn = sqlite3.connect('store.db')
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_pass, session['user']))
            conn.commit()
            conn.close()
            return redirect(url_for('index', success='تم تحديث كلمة السر بنجاح!'))
    return redirect(url_for('index', error='حدث خطأ'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/add_merchant', methods=['POST'])
def add_merchant():
    if session.get('user'):
        name = request.form.get('name')
        phone = request.form.get('phone')
        details = request.form.get('details')
        conn = sqlite3.connect('store.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO merchants (name, phone, details) VALUES (?, ?, ?)", (name, phone, details))
        conn.commit()
        conn.close()
    return redirect(url_for('index'))

@app.route('/add_purchase', methods=['POST'])
def add_purchase():
    if session.get('user'):
        merchant_name = request.form.get('merchant_name')
        item = request.form.get('item')
        quantity = request.form.get('quantity')
        price = request.form.get('price')
        date = request.form.get('date')
        conn = sqlite3.connect('store.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO purchases (merchant_name, item, quantity, price, date) VALUES (?, ?, ?, ?, ?)", 
                       (merchant_name, item, quantity, price, date))
        conn.commit()
        conn.close()
    return redirect(url_for('index'))

@app.route('/add_payment', methods=['POST'])
def add_payment():
    if session.get('user'):
        merchant_name = request.form.get('merchant_name')
        amount = request.form.get('amount')
        date = request.form.get('date')
        conn = sqlite3.connect('store.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO payments (merchant_name, amount, date) VALUES (?, ?, ?)", 
                       (merchant_name, amount, date))
        conn.commit()
        conn.close()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
