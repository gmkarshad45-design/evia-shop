import os
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- 1. CONFIGURATION ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'evia_premium_2026')
database_url = os.environ.get("DATABASE_URL", "sqlite:///evia_v9.db")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- 2. MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)
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
    date_ordered = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

# --- 3. ROUTES ---
@app.route('/')
def index():
    products = Product.query.all()
    cart = session.get('cart', [])
    return render_template('index.html', products=products, cart_count=len(cart))

# --- 4. CART LOGIC (FIXED) ---
@app.route('/add-to-cart/<int:id>')
def add_to_cart(id):
    if 'cart' not in session: session['cart'] = []
    cart = list(session['cart'])
    cart.append(id)
    session['cart'] = cart
    session.modified = True 
    return redirect(url_for('index'))

@app.route('/buy-now/<int:id>')
def buy_now(id):
    session['cart'] = [id]
    session.modified = True
    return redirect(url_for('cart_view'))

@app.route('/cart')
def cart_view():
    cart_ids = session.get('cart', [])
    items = []
    total = 0
    for p_id in cart_ids:
        p = Product.query.get(p_id)
        if p:
            items.append(p)
            total += p.price
    return render_template('cart.html', items=items, total=total)

# ADDED THIS TO FIX YOUR LOG ERROR:
@app.route('/remove-from-cart/<int:id>')
def remove_from_cart(id):
    if 'cart' in session:
        cart = list(session['cart'])
        if id in cart:
            cart.remove(id)
            session['cart'] = cart
            session.modified = True
    return redirect(url_for('cart_view'))

# --- 5. CHECKOUT ---
@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    cart_ids = session.get('cart', [])
    if not cart_ids: return redirect(url_for('index'))
    
    items = [Product.query.get(p_id) for p_id in cart_ids if Product.query.get(p_id)]
    details = ", ".join([p.name for p in items])
    total = sum(p.price for p in items)
    
    new_order = Order(product_details=details, total_price=total, user_id=current_user.id)
    db.session.add(new_order)
    db.session.commit()
    session.pop('cart', None)
    return redirect(url_for('profile'))

# --- 6. AUTH & PROFILE ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        pw = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256')
        new_user = User(full_name=request.form.get('full_name'), email=request.form.get('email'), password=pw)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('index'))
    return render_template('signup.html')

@app.route('/profile')
@login_required
def profile():
    orders = Order.query.filter_by(user_id=current_user.id).all()
    return render_template('profile.html', orders=orders)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin_panel():
    if current_user.email != 'admin@test.gmail.com': return "Denied", 403
    return render_template('admin.html', orders=Order.query.all())

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
