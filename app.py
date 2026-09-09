from flask import Flask, render_template_string, request, redirect, url_for

app = Flask(__name__)

# قائمة مؤقتة لتخزين العناصر (إدارة المخزون الخاصة بأبو الأمير)
inventory = [
    {"id": 1, "name": "أجهزة حاسوب", "quantity": 10, "price": 350},
    {"id": 2, "name": "شاشات عرض", "quantity": 5, "price": 120}
]

@app.route('/')
def index():
    total_items = sum(item['quantity'] for item in inventory)
    return render_template_string('''
    <!doctype html>
    <html lang="ar" dir="rtl">
      <head>
        <meta charset="utf-8">
        <title>نظام إدارة المخزون - أبو الأمير</title>
        <style>
          body { font-family: Tahoma, sans-serif; background-color: #f4f7f6; margin: 0; padding: 20px; }
          .container { max-width: 800px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
          h1 { color: #333; text-align: center; }
          table { width: 100%%; border-collapse: collapse; margin-top: 20px; }
          th, td { border: 1px solid #ddd; padding: 10px; text-align: center; }
          th { background-color: #007bff; color: white; }
          form { margin-top: 20px; background: #f9f9f9; padding: 15px; border-radius: 5px; }
          input { padding: 8px; margin: 5px; width: calc(30%% - 10px); }
          button { padding: 8px 15px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; }
          button:hover { background: #218838; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>نظام إدارة المخزون - أبو الأمير</h1>
          <p>إجمالي القطع في المخزن: <strong>{{ total_items }}</strong></p>
          <table>
            <tr>
              <th>المعرف</th>
              <th>اسم المادة</th>
              <th>الكمية</th>
              <th>السعر ($)</th>
            </tr>
            {% for item in inventory %}
            <tr>
              <td>{{ item.id }}</td>
              <td>{{ item.name }}</td>
              <td>{{ item.quantity }}</td>
              <td>{{ item.price }}</td>
            </tr>
            {% endfor %}
          </table>
          
          <form action="/add" method="POST">
            <h3>إضافة مادة جديدة للمخزن</h3>
            <input type="text" name="name" placeholder="اسم المادة" required>
            <input type="number" name="quantity" placeholder="الكمية" required>
            <input type="number" name="price" placeholder="السعر" required>
            <br>
            <button type="submit">إضافة للمخزن</button>
          </form>
        </div>
      </body>
    </html>
    ''', inventory=inventory, total_items=total_items)

@app.route('/add', methods=['POST'])
def add_item():
    name = request.form.get('name')
    quantity = int(request.form.get('quantity', 0))
    price = float(request.form.get('price', 0.0))
    new_id = len(inventory) + 1
    inventory.append({"id": new_id, "name": name, "quantity": quantity, "price": price})
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
