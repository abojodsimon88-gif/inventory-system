from flask import Flask, render_template_string, request, redirect, url_for, session
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'tyre_shop_secure_2026'

# جعل الجلسة تنتهي بمجرد إغلاق المتصفح لضمان طلب كلمة السر دائماً
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

USERS = {
    'admin': '0000'
}

INVENTORY = {}
DAILY_LOG = []
WORK_LOG = []  # سجل الشغل اليومي (قديش اشتغلت اليوم)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>نظام إدارة مخزون البناشر الذكي</title>
    <style>
        body { font-family: Tahoma, sans-serif; background-color: #f0f2f5; margin: 0; padding: 15px; color: #333; }
        .container { max-width: 1000px; margin: auto; background: white; padding: 15px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #2c3e50; text-align: center; font-size: 22px; }
        .btn { display: inline-block; background: #3498db; color: white; padding: 10px 15px; text-decoration: none; border-radius: 5px; margin: 5px 0; border: none; cursor: pointer; width: 100%%; text-align: center; font-size: 16px; box-sizing: border-box; }
        .btn:hover { background: #2980b9; }
        .btn-danger { background: #e74c3c; width: auto; padding: 5px 10px; }
        .btn-danger:hover { background: #c0392b; }
        .btn-success { background: #27ae60; }
        .btn-success:hover { background: #219653; }
        .btn-warning { background: #f39c12; color: white; width: auto; padding: 5px 10px; }
        .btn-warning:hover { background: #d68910; }
        table { width: 100%%; border-collapse: collapse; margin-top: 15px; font-size: 14px; overflow-x: auto; display: block; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: center; }
        th { background-color: #2c3e50; color: white; }
        select, input { width: 100%%; padding: 10px; margin: 5px 0 15px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; font-family: Tahoma; font-size: 15px; background: #fff; }
        .card { background: #fdfdfd; border: 1px solid #e2e8f0; padding: 12px; border-radius: 6px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.02); }
        .error { background: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; margin-bottom: 15px; text-align: center; }
        .success-msg { background: #d4edda; color: #155724; padding: 10px; border-radius: 5px; margin-bottom: 15px; text-align: center; }
        .section-container { display: flex; flex-direction: column; gap: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛞 نظام إدارة مخزون البناشر الذكي</h1>
        
        {% if session.get('user') %}
            <div style="display: flex; justify-content: space-between; align-items: center; background: #e2e8f0; padding: 10px; border-radius: 5px; margin-bottom: 15px; font-size: 14px;">
                <span>المستخدم: <strong>{{ session.get('user') }}</strong></span>
                <a href="/logout" class="btn btn-danger" style="padding: 5px 10px; margin: 0; font-size: 13px;">تسجيل خروج</a>
            </div>

            {% if error %}
                <div class="error">{{ error }}</div>
            {% endif %}
            {% if success %}
                <div class="success-msg">{{ success }}</div>
            {% endif %}

            <!-- قسم تغيير كلمة السر -->
            <div class="card" style="background: #f8fafc;">
                <h4 style="margin: 0 0 10px 0; font-size: 16px;">🔐 تغيير كلمة السر</h4>
                <form method="POST" action="/change_password">
                    <label>كلمة السر الجديدة:</label>
                    <input type="password" name="new_password" required placeholder="أدخل كلمة السر الجديدة">
                    <button type="submit" class="btn btn-success">تحديث كلمة السر</button>
                </form>
            </div>

            <div class="section-container">
                <!-- قسم تسجيل الشغل اليومي (قديش اشتغلت اليوم) -->
                <div class="card" style="border-right: 5px solid #e67e22;">
                    <h3 style="margin-top:0;">💵 تسجيل الشغل اليومي (أجرة اليد / الخدمات)</h3>
                    <form method="POST" action="/add_work">
                        <label>تفاصيل الشغل (مثلاً: تركيب كوشوك، ترصيص، بنشر...):</label>
                        <input type="text" name="work_desc" required placeholder="اكتب وصف الشغل هنا...">

                        <label>المبلغ (بالشيكل):</label>
                        <input type="number" step="0.01" name="work_amount" required placeholder="0.00">

                        <button type="submit" class="btn" style="background: #e67e22;">تسجيل شغل اليوم</button>
                    </form>
                </div>

                <!-- قسم حركة المخزون التلقائية السريعة -->
                <div class="card" style="border-right: 5px solid #3498db;">
                    <h3 style="margin-top:0;">⚡ حركة المخزون التلقائية (بيع / شراء)</h3>
                    <form method="POST" action="/daily_transaction">
                        <label>نوع العملية:</label>
                        <select name="action_type">
                            <option value="بيع (إخراج من المخزون)">📉 بيع (ينقص المخزون تلقائياً)</option>
                            <option value="شراء (توريد للمخزون)">📈 شراء / توريد (يزيد المخزون تلقائياً)</option>
                        </select>

                        <label>اختر الصنف المتوفر:</label>
                        <select name="item_name">
                            <option value="">--- اختر صنفاً من المخزون ---</option>
                            {% for item in inventory.keys() %}
                                <option value="{{ item }}">{{ item }} (المتوفر: {{ inventory[item].qty }})</option>
                            {% endfor %}
                        </select>

                        <label>أو اكتب اسم صنف جديد (عند التوريد/الشراء):</label>
                        <input type="text" name="new_item_name" placeholder="اكتب اسم الصنف الجديد هنا...">

                        <label>الكمية:</label>
                        <input type="number" name="quantity" min="1" required placeholder="الكمية">

                        <button type="submit" class="btn">تنفيذ وتحديث المخزون تلقائياً</button>
                    </form>
                </div>

                <!-- قسم إدارة وإضافة صنف جديد / تعديل صنف -->
                <div class="card" style="border-right: 5px solid #27ae60;">
                    <h3 style="margin-top:0;">➕ إضافة أو تعديل صنف بالمخزون</h3>
                    <form method="POST" action="/save_item">
                        <label>اسم الصنف:</label>
                        <input type="text" name="item_name" required placeholder="اسم الصنف">

                        <label>الكمية الكلية:</label>
                        <input type="number" name="qty" required placeholder="الكمية">

                        <label>سعر الشراء:</label>
                        <input type="number" step="0.01" name="buy_price" required placeholder="0.00">

                        <label>سعر البيع:</label>
                        <input type="number" step="0.01" name="sell_price" required placeholder="0.00">

                        <button type="submit" class="btn btn-success">حفظ أو تعديل الصنف</button>
                    </form>
                </div>
            </div>

            <!-- جدول سجل الشغل اليومي -->
            <h2>📋 سجل الشغل اليومي (أجرة اليد والخدمات)</h2>
            <table>
                <tr>
                    <th>الوقت</th>
                    <th>تفاصيل العمل</th>
                    <th>المبلغ</th>
                </tr>
                {% for work in work_log %}
                    <tr>
                        <td>{{ work.time }}</td>
                        <td>{{ work.desc }}</td>
                        <td><strong style="color: #27ae60;">{{ work.amount }} شيكل</strong></td>
                    </tr>
                {% else %}
                    <tr><td colspan="3">لم يتم تسجيل أي شغل اليوم حتى الآن.</td></tr>
                {% endfor %}
            </table>

            <!-- جدول المخزون الكلي -->
            <h2 style="margin-top: 25px;">📦 المخزون الكلي للمحل</h2>
            <table>
                <tr>
                    <th>الصنف</th>
                    <th>الكمية المتوفرة</th>
                    <th>شراء</th>
                    <th>بيع</th>
                    <th>إجراءات</th>
                </tr>
                {% for item, data in inventory.items() %}
                    <tr>
                        <td><strong>{{ item }}</strong></td>
                        <td>{{ data.qty }}</td>
                        <td>{{ data.buy_price }}</td>
                        <td>{{ data.sell_price }}</td>
                        <td>
                            <button onclick="editItem('{{ item }}', '{{ data.qty }}', '{{ data.buy_price }}', '{{ data.sell_price }}')" class="btn btn-warning">تعديل</button>
                            <a href="/delete_item?item={{ item }}" class="btn btn-danger" onclick="return confirm('متأكد بدك تحذف هذا الصنف؟')">حذف</a>
                        </td>
                    </tr>
                {% else %}
                    <tr><td colspan="5">لا توجد أصناف مخزنة حالياً. ابدأ بإضافة أصناف جديدة.</td></tr>
                {% endfor %}
            </table>

            <!-- سجل حركات المخزون -->
            <h2 style="margin-top: 25px;">📊 سجل حركات المخزون</h2>
            <table>
                <tr>
                    <th>الوقت</th>
                    <th>نوع الحركة</th>
                    <th>الصنف</th>
                    <th>الكمية</th>
                    <th>التأثير التلقائي</th>
                </tr>
                {% for log in daily_log %}
                    <tr>
                        <td>{{ log.time }}</td>
                        <td>
                            {% if 'بيع' in log.type %}
                                <span style="color: #e74c3c; font-weight: bold;">{{ log.type }}</span>
                            {% else %}
                                <span style="color: #27ae60; font-weight: bold;">{{ log.type }}</span>
                            {% endif %}
                        </td>
                        <td>{{ log.item }}</td>
                        <td>{{ log.qty }}</td>
                        <td>{{ log.effect }}</td>
                    </tr>
                {% else %}
                    <tr><td colspan="5">لم يتم تسجيل أي حركات مخزون اليوم.</td></tr>
                {% endfor %}
            </table>

        {% else %}
            <!-- صفحة تسجيل الدخول -->
            <div class="card" style="max-width: 350px; margin: 30px auto; text-align: center;">
                <h2>تسجيل الدخول</h2>
                {% if error %}
                    <div class="error">{{ error }}</div>
                {% endif %}
                <form method="POST" action="/login">
                    <label>اسم المستخدم:</label>
                    <input type="text" name="username" required placeholder="admin">

                    <label>كلمة السر (0000):</label>
                    <input type="password" name="password" required placeholder="كلمة السر">

                    <button type="submit" class="btn" style="width: 100%;">دخول</button>
                </form>
            </div>
        {% endif %}
    </div>

    <script>
        function editItem(name, qty, buy, sell) {
            document.querySelector('input[name="item_name"]').value = name;
            document.querySelector('input[name="qty"]').value = qty;
            document.querySelector('input[name="buy_price"]').value = buy;
            document.querySelector('input[name="sell_price"]').value = sell;
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE, 
                                  inventory=INVENTORY, 
                                  daily_log=DAILY_LOG,
                                  work_log=WORK_LOG,
                                  error=request.args.get('error'),
                                  success=request.args.get('success'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if username in USERS and USERS[username] == password:
        session.permanent = True
        session['user'] = username
        return redirect(url_for('index'))
    else:
        return redirect(url_for('index', error='خطأ في اسم المستخدم أو كلمة السر!'))

@app.route('/change_password', methods=['POST'])
def change_password():
    if session.get('user'):
        new_pass = request.form.get('new_password')
        if new_pass:
            USERS[session['user']] = new_pass
            return redirect(url_for('index', success='تم تحديث كلمة السر بنجاح!'))
    return redirect(url_for('index', error='حدث خطأ أثناء التحديث'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/add_work', methods=['POST'])
def add_work():
    if session.get('user'):
        work_desc = request.form.get('work_desc').strip()
        try:
            work_amount = float(request.form.get('work_amount'))
            current_time = datetime.now().strftime('%H:%M:%S')
            
            WORK_LOG.insert(0, {
                'time': current_time,
                'desc': work_desc,
                'amount': work_amount
            })
            return redirect(url_for('index', success='تم تسجيل الشغل اليومي بنجاح!'))
        except ValueError:
            return redirect(url_for('index', error='الرجاء إدخال مبلغ صحيح.'))
    return redirect(url_for('index'))

@app.route('/save_item', methods=['POST'])
def save_item():
    if session.get('user'):
        item_name = request.form.get('item_name').strip()
        try:
            qty = int(request.form.get('qty'))
            buy_price = float(request.form.get('buy_price'))
            sell_price = float(request.form.get('sell_price'))
            
            INVENTORY[item_name] = {
                'qty': qty,
                'buy_price': buy_price,
                'sell_price': sell_price
            }
            return redirect(url_for('index', success=f'تم حفظ الصنف ({item_name}) بنجاح!'))
        except ValueError:
            return redirect(url_for('index', error='الرجاء إدخال أرقام صحيحة للكمية والأسعار.'))
    return redirect(url_for('index'))

@app.route('/delete_item')
def delete_item():
    if session.get('user'):
        item = request.args.get('item')
        if item in INVENTORY:
            del INVENTORY[item]
            return redirect(url_for('index', success=f'تم حذف الصنف ({item}) بنجاح!'))
    return redirect(url_for('index'))

@app.route('/daily_transaction', methods=['POST'])
def daily_transaction():
    if session.get('user'):
        action_type = request.form.get('action_type')
        item_name = request.form.get('item_name')
        new_item_name = request.form.get('new_item_name').strip()
        
        if new_item_name and 'شراء' in action_type:
            item_name = new_item_name
            if item_name not in INVENTORY:
                INVENTORY[item_name] = {'qty': 0, 'buy_price': 0, 'sell_price': 0}

        try:
            quantity = int(request.form.get('quantity'))
        except ValueError:
            return redirect(url_for('index', error='الكمية يجب أن تكون رقماً صحيحاً.'))
        
        if item_name in INVENTORY:
            current_time = datetime.now().strftime('%H:%M:%S')
            
            if 'بيع' in action_type:
                if INVENTORY[item_name]['qty'] >= quantity:
                    INVENTORY[item_name]['qty'] -= quantity
                    effect = f"تم خصم {quantity} قطعة تلقائياً"
                else:
                    return redirect(url_for('index', error='الكمية المباعة أكبر من المتوفر بالمخزون الحالي!'))
            else:
                INVENTORY[item_name]['qty'] += quantity
                effect = f"تم إضافة {quantity} قطعة تلقائياً"
            
            DAILY_LOG.insert(0, {
                'time': current_time,
                'type': action_type,
                'item': item_name,
                'qty': quantity,
                'effect': effect
            })
            return redirect(url_for('index', success='تمت الحركة وتحديث المخزون تلقائياً بنجاح!'))
        else:
            return redirect(url_for('index', error='الرجاء اختيار صنف صحيح أو إدخال صنف جديد للتوريد.'))
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
