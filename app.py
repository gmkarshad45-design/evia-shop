import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'evia_secret_2025')

# Database Setup
database_url = os.environ.get("DATABASE_URL", "sqlite:///evia.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    orders = db.relationship('Order', backref='customer', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(500)) 
    image_2 = db.Column(db.String(500)) 
    description = db.Column(db.Text)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_details = db.Column(db.Text)
    total_price = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    whatsapp = db.Column(db.String(20))
    address = db.Column(db.Text)
    status = db.Column(db.String(50), default="Pending")
    date_ordered = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- USER ROUTES ---
@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart_ids = session.get('cart', [])
    items = Product.query.filter(Product.id.in_(cart_ids)).all() if cart_ids else []
    if not items: return redirect(url_for('index'))
    total = sum(i.price for i in items)

    if request.method == 'POST':
        full_addr = f"{request.form.get('address')}, {request.form.get('district')} - {request.form.get('pincode')}"
        new_order = Order(
            product_details=", ".join([p.name for p in items]),
            total_price=total,
            user_id=current_user.id,
            whatsapp=request.form.get('whatsapp'),
            address=full_addr
        )
        db.session.add(new_order)
        db.session.commit()
        session.pop('cart', None)
        flash("ORDER_SUCCESS")
        return redirect(url_for('checkout'))
    return render_template('checkout.html', total=total, items=items)

# --- ADMIN ROUTES ---
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if not current_user.is_admin: return redirect(url_for('index'))
    if request.method == 'POST':
        new_p = Product(
            name=request.form.get('name'),
            price=request.form.get('price'),
            image=request.form.get('image'),
            image_2=request.form.get('image_2'),
            description=request.form.get('description')
        )
        db.session.add(new_p)
        db.session.commit()
        return redirect(url_for('admin_panel'))
    
    products = Product.query.all()
    orders = Order.query.order_by(Order.date_ordered.desc()).all()
    return render_template('admin.html', products=products, orders=orders)

@app.route('/admin/status/<int:id>/<string:st>')
@login_required
def update_status(id, st):
    if current_user.is_admin:
        o = Order.query.get(id)
        o.status = st
        db.session.commit()
    return redirect(url_for('admin_panel'))

# --- CRITICAL SETUP ROUTE ---
@app.route('/setup-admin-99')
def setup_admin():
    db.drop_all()
    db.create_all()
    admin_user = User(
        full_name="Admin",
        email="admin@test.gmail.com",
        password=generate_password_hash('admin123', method='pbkdf2:sha256'),
        is_admin=True
    )
    db.session.add(admin_user)
    db.session.commit()
    return "DATABASE FIXED! Login: admin@test.gmail.com | Pass: admin123"

# --- AUTH ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('admin_panel' if user.is_admin else 'index'))
    return '''<form method="POST">Email: <input name="email"><br>Pass: <input type="password" name="password"><br><button>Login</button></form>'''

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
