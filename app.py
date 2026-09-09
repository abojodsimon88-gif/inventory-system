from flask import Flask, render_template_string, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'tyre_shop_secret_2026'

# --- بيانات المستخدمين وكلمة السر ---
USERS = {
    'admin': '0000' # اسم المستخدم الافتراضي وكلمة السر
}

# --- قاعدة بيانات مؤقتة للمخزون (اسم البضاعة -> الكمية، سعر الشراء، سعر البيع) ---
INVENTORY = {
    'كوشوك هانكوك 16': {'qty': 40, 'buy_price': 220, 'sell_price': 260},
    'كوشوك كومهو 15': {'qty': 25, 'buy_price': 180, 'sell_price': 210},
    'ترصيص وتجليد': {'qty': 100, 'buy_price': 5, 'sell_price': 15}
}

# --- سجل الشغل اليومي (بيع وشراء) ---
DAILY_LOG = []

# --- الواجهة البرمجية (HTML) ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>نظام إدارة مخزون البناشر والشغل اليومي</title>
    <style>
        body { font-family: Tahoma, sans-serif; background-color: #f0f2f5; margin: 0; padding: 20px; color: #333; }
        .container { max-width: 1000px; margin: auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #2c3e50; text-align: center; }
        .btn { display: inline-block; background: #3498db; color: white; padding: 8px 15px; text-decoration: none; border-radius: 5px; margin: 3px; border: none; cursor: pointer; }
        .btn:hover { background: #2980b9; }
        .btn-danger { background: #e74c3c; }
        .btn-danger:hover { background: #c0392b; }
        .btn-success { background: #27ae60; }
        .btn-success:hover { background: #219653; }
        .btn-warning { background: #f39c12; color: white; }
        .btn-warning:hover { background: #d68910; }
        table { width: 100%%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: center; }
        th { background-color: #2c3e50; color: white; }
        select, input { width: 100%%; padding: 8px; margin: 5px 0 15px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; font-family: Tahoma; }
        .card { background: #fdfdfd; border: 1px solid #e2e8f0; padding: 15px; border-radius: 6px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.02); }
        .error { background: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; margin-bottom: 15px; text-align: center; }
        .success-msg { background: #d4edda; color: #155724; padding: 10px; border-radius: 5px; margin-bottom: 15px; text-align: center; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛞 نظام إدارة مخزون البناشر الذكي</h1>
        
        {% if session.get('user') %}
            <div style="display: flex; justify-content: space-between; align-items: center; background: #e2e8f0; padding: 10px 15px; border-radius: 5px; margin-bottom: 20px;">
                <span>مرحباً بك، المستخدم: <strong>{{ session.get('user') }}</strong></span>
                <a href="/logout" class="btn btn-danger" style="padding: 5px 10px; margin: 0;">تسجيل خروج</a>
            </div>

            {% if error %}
                <div class="error">{{ error }}</div>
            {% endif %}
            {% if success %}
                <div class="success-msg">{{ success }}</div>
            {% endif %}

            <!-- قسم تغيير كلمة السر -->
            <div class="card" style="background: #f8fafc;">
                <h4>🔐 تغيير كلمة السر الخاصة بك</h4>
                <form method="POST" action="/change_password" style="display: flex; gap: 10px; align-items: flex-end;">
                    <div style="flex: 1; margin: 0;">
                        <label>كلمة السر الجديدة:</label>
                        <input type="password" name="new_password" required placeholder="أدخل كلمة السر الجديدة">
                    </div>
                    <button type="submit" class="btn btn-success" style="height: 38px; margin: 0;">تحديث كلمة السر</button>
                </form>
            </div>

            <div class="grid-2">
                <!-- قسم تسجيل الشغل اليومي الذكي (بيع / شراء سريع) -->
                <div class="card" style="border-right: 5px solid #3498db;">
                    <h3>⚡ تسجيل حركة سريعة (بيع أو شراء)</h3>
                    <p style="font-size: 13px; color: #666;">النظام سيقوم بتعديل المخزون تلقائياً بالزيادة أو النقصان!</p>
                    <form method="POST" action="/daily_transaction">
                        <label>نوع الحركة:</label>
                        <select name="action_type">
                            <option value="بيع">بيع (ينقص من المخزون تلقائياً)</option>
                            <option value="شراء">شراء / توريد (يزيد المخزون تلقائياً)</option>
                        </select>

                        <label>اختر الصنف (أو اكتبه إذا كان شراء صنف جديد):</label>
                        <select name="item_name" required>
                            {% for item in inventory.keys() %}
                                <option value="{{ item }}">{{ item }} (المتوفر: {{ inventory[item].qty }})</option>
                            {% endfor %}
                        </select>
                        <input type="text" name="new_item_name" placeholder="أو اكتب اسم صنف جديد (في حال الشراء)..." style="margin-top: -10px;">

                        <label>الكمية:</label>
                        <input type="number" name="quantity" min="1" required placeholder="الكمية">

                        <button type="submit" class="btn" style="width: 100%;">تنفيذ الحركة وتحديث المخزون فورا</button>
                    </form>
                </div>

                <!-- قسم إضافة صنف جديد أو تعديل صنف بالمخزون الكلي -->
                <div class="card" style="border-right: 5px solid #27ae60;">
                    <h3>➕ إدارة وتعديل المخزون الكلي</h3>
                    <form method="POST" action="/save_item">
                        <label>اسم الصنف:</label>
                        <input type="text" name="item_name" required placeholder="اسم الصنف المراد إضافته أو تعديله">

                        <label>الكمية الكلية:</label>
                        <input type="number" name="qty" required placeholder="الكمية">

                        <div style="display: flex; gap: 10px;">
                            <div style="flex: 1;">
                                <label>سعر الشراء:</label>
                                <input type="number" step="0.01" name="buy_price" required placeholder="0.00">
                            </div>
                            <div style="flex: 1;">
                                <label>سعر البيع:</label>
                                <input type="number" step="0.01" name="sell_price" required placeholder="0.00">
                            </div>
                        </div>

                        <button type="submit" class="btn btn-success" style="width: 100%;">حفظ / تعديل الصنف</button>
                    </form>
                </div>
            </div>

            <!-- عرض المخزون الكلي للمحل مع زر تعديل مباشر -->
            <h2>📦 المخزون الكلي للمحل</h2>
            <table>
                <tr>
                    <th>اسم الصنف / البضاعة</th>
                    <th>الكمية المتوفرة</th>
                    <th>سعر الشراء</th>
                    <th>سعر البيع</th>
                    <th>إجراءات</th>
                </tr>
                {% for item, data in inventory.items() %}
                    <tr>
                        <td><strong>{{ item }}</strong></td>
                        <td><span style="background: #e2e8f0; padding: 3px 8px; border-radius: 4px; font-weight: bold;">{{ data.qty }}</span></td>
                        <td>{{ data.buy_price }}</td>
                        <td>{{ data.sell_price }}</td>
                        <td>
                            <button onclick="editItem('{{ item }}', '{{ data.qty }}', '{{ data.buy_price }}', '{{ data.sell_price }}')" class="btn btn-warning" style="padding: 3px 8px; font-size: 13px;">تعديل</button>
                            <a href="/delete_item?item={{ item }}" class="btn btn-danger" style="padding: 3px 8px; font-size: 13px;" onclick="return confirm('متأكد بدك تحذف هذا الصنف؟')">حذف</a>
                        </td>
                    </tr>
                {% else %}
                    <tr><td colspan="5">لا توجد أصناف مخزنة حالياً.</td></tr>
                {% endfor %}
            </table>

            <!-- سجل الشغل اليومي -->
            <h2 style="margin-top: 30px;">📊 سجل الحركات اليومية (بيع وشراء)</h2>
            <table>
                <tr>
                    <th>نوع الحركة</th>
                    <th>الصنف</th>
                    <th>الكمية</th>
                    <th>التأثير على المخزون</th>
                </tr>
                {% for log in daily_log %}
                    <tr>
                        <td>
                            {% if log.type == 'بيع' %}
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
                    <tr><td colspan="4">لم يتم تسجيل أي حركات اليوم.</td></tr>
                {% endfor %}
            </table>

        {% else %}
            <!-- صفحة تسجيل الدخول -->
            <div class="card" style="max-width: 400px; margin: 40px auto; text-align: center;">
                <h2>تسجيل الدخول للنظام</h2>
                {% if error %}
                    <div class="error">{{ error }}</div>
                {% endif %}
                <form method="POST" action="/login">
                    <label>اسم المستخدم:</label>
                    <input type="text" name="username" required placeholder="أدخل اسم المستخدم (admin)">

                    <label>كلمة السر (الافتراضية: 0000):</label>
                    <input type="password" name="password" required placeholder="أدخل كلمة السر">

                    <button type="submit" class="btn" style="width: 100%;">دخول للنظام</button>
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
                                  error=request.args.get('error'),
                                  success=request.args.get('success'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username in USERS and USERS[username] == password:
        session['user'] = username
        return redirect(url_for('index'))
    else:
        return redirect(url_for('index', error='اسم المستخدم أو كلمة السر غير صحيحة! (الافتراضي: admin / 0000)'))

@app.route('/change_password', methods=['POST'])
def change_password():
    if session.get('user'):
        new_pass = request.form.get('new_password')
        if new_pass:
            user = session.get('user')
            USERS[user] = new_pass
            return redirect(url_for('index', success='تم تحديث كلمة السر بنجاح!'))
    return redirect(url_for('index', error='حدث خطأ أثناء تغيير كلمة السر'))

@app.route('/logout')
def logout():
    session.pop('user', None)
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
            return redirect(url_for('index', success=f'تم حفظ الصنف ({item_name}) وتحديث المخزون بنجاح!'))
        except ValueError:
            return redirect(url_for('index', error='الرجاء إدخال أرقام صحيحة للكمية والأسعار.'))
    return redirect(url_for('index'))

@app.route('/delete_item')
def delete_item():
    if session.get('user'):
        item = request.args.get('item')
        if item in INVENTORY:
            del INVENTORY[item]
            return redirect(url_for('index', success=f'تم حذف الصنف ({item}) من المخزون بنجاح!'))
    return redirect(url_for('index'))

@app.route('/daily_transaction', methods=['POST'])
def daily_transaction():
    if session.get('user'):
        action_type = request.form.get('action_type')
        item_name = request.form.get('item_name')
        new_item_name = request.form.get('new_item_name').strip()
        
        # لو كتب صنف جديد في حالة الشراء
        if new_item_name and action_type == 'شراء':
            item_name = new_item_name
            if item_name not in INVENTORY:
                # افتراض أسعار مبدئية لو الصنف جديد تماماً ويمكنه تعديلها لاحقاً
                INVENTORY[item_name] = {'qty': 0, 'buy_price': 0, 'sell_price': 0}

        try:
            quantity = int(request.form.get('quantity'))
        except ValueError:
            return redirect(url_for('index', error='الكمية يجب أن تكون رقماً صحيحاً.'))
        
        if item_name in INVENTORY:
            if action_type == 'بيع':
                if INVENTORY[item_name]['qty'] >= quantity:
                    INVENTORY[item_name]['qty'] -= quantity
                    effect = f"تم خصم {quantity} قطعة من المخزون"
                else:
                    return redirect(url_for('index', error='الكمية المطلوبة للبيع أكبر من المتوفر في المخزون!'))
            elif action_type == 'شراء':
                INVENTORY[item_name]['qty'] += quantity
                effect = f"تم إضافة {quantity} قطعة للمخزون"
            
            DAILY_LOG.insert(0, {
                'type': action_type,
                'item': item_name,
                'qty': quantity,
                'effect': effect
            })
            return redirect(url_for('index', success='تمت العملية وتحديث المخزون تلقائياً بنجاح!'))
        else:
            return redirect(url_for('index', error='الصنف غير موجود بالمخزون!'))
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
