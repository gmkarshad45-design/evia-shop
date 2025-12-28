import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'evia_pro_ultra_2025')

# --- DATABASE SETUP ---
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///evia_db.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    orders = db.relationship('Order', backref='customer', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(500)) 
    description = db.Column(db.Text)    

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_details = db.Column(db.Text) 
    total_price = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(50), default="Placed")
    date_ordered = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- SHOP & CART ROUTES ---

@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/add_to_cart/<int:id>')
def add_to_cart(id):
    if 'cart' not in session:
        session['cart'] = []
    cart_list = list(session['cart'])
    cart_list.append(id)
    session['cart'] = cart_list
    session.modified = True
    flash("Item added to bag!")
    return redirect(url_for('index'))

@app.route('/cart')
def cart():
    cart_ids = session.get('cart', [])
    # Fetch actual product objects for the IDs in session
    products = Product.query.filter(Product.id.in_(cart_ids)).all() if cart_ids else []
    total = sum(p.price for p in products)
    return render_template('cart.html', products=products, total=total)

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart_ids = session.get('cart', [])
    items = Product.query.filter(Product.id.in_(cart_ids)).all() if cart_ids else []
    
    if not items:
        flash("Your cart is empty.")
        return redirect(url_for('index'))

    total = sum(i.price for i in items)

    if request.method == 'POST':
        # Create a string of item names for the order record
        item_names = ", ".join([p.name for p in items])
        new_order = Order(
            product_details=item_names,
            total_price=total,
            user_id=current_user.id,
            status="Placed"
        )
        db.session.add(new_order)
        db.session.commit()
        session.pop('cart', None) # Clear cart
        flash("Order placed successfully!")
        return redirect(url_for('profile'))

    return render_template('checkout.html', total=total, items=items)

# --- ADMIN PANEL ROUTE ---

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash("Access Denied.")
        return redirect(url_for('index'))
    
    all_orders = Order.query.order_by(Order.id.desc()).all()
    all_users = User.query.all()
    return render_template('admin.html', orders=all_orders, users=all_users)

# --- AUTH & SYSTEM ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        flash("Login failed.")
    return render_template('login.html')

@app.route('/profile')
@login_required
def profile():
    orders = Order.query.filter_by(user_id=current_user.id).all()
    return render_template('profile.html', orders=orders)

@app.route('/setup-admin-99')
def setup_admin():
    db.drop_all()
    db.create_all()
    admin_pw = generate_password_hash('admin123', method='pbkdf2:sha256')
    admin = User(full_name="Admin", email="admin@test.gmail.com", password=admin_pw, is_admin=True)
    p = Product(name="Pro Watch", price=1200, description="Luxury Item", image="")
    db.session.add(admin)
    db.session.add(p)
    db.session.commit()
    return "Database reset! Admin created. Email: admin@test.gmail.com | Pass: admin123"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
