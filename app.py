import os
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- 1. CONFIGURATION ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'evia_premium_key_2026')
database_url = os.environ.get("DATABASE_URL", "sqlite:///evia_final_v7.db")
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

# --- 3. AUTO-INIT DATABASE ---
with app.app_context():
    db.create_all()

# --- 4. ROUTES ---
@app.route('/')
def index():
    products = Product.query.all()
    # Safely get cart count
    cart = session.get('cart', [])
    cart_count = len(cart) if isinstance(cart, list) else 0
    return render_template('index.html', products=products, cart_count=cart_count)

@app.route('/product/<int:id>')
def product_detail(id):
    product = Product.query.get_or_404(id)
    return render_template('product_detail.html', product=product)

# --- 5. FIXED CART LOGIC ---
@app.route('/add-to-cart/<int:id>')
def add_to_cart(id):
    if 'cart' not in session or not isinstance(session['cart'], list):
        session['cart'] = []
    
    cart = list(session['cart'])
    cart.append(id)
    session['cart'] = cart
    session.modified = True 
    flash("Item added to bag!")
    return redirect(url_for('index'))

@app.route('/buy-now/<int:id>')
def buy_now(id):
    session['cart'] = [id] # Reset cart to only this item
    session.modified = True
    return redirect(url_for('cart_view'))

@app.route('/cart')
def cart_view():
    cart_ids = session.get('cart', [])
    if not isinstance(cart_ids, list):
        cart_ids = []
    
    items = []
    total = 0
    for p_id in cart_ids:
        p = Product.query.get(p_id)
        if p:
            items.append(p)
            total += p.price
            
    return render_template('cart.html', items=items, total=total)

# --- 6. AUTHENTICATION ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256')
        new_user = User(full_name=request.form.get('full_name'), email=request.form.get('email'), password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('index'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- 7. PROFILE & ADMIN ---
@app.route('/profile')
@login_required
def profile():
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.date_ordered.desc()).all()
    return render_template('profile.html', orders=orders)

@app.route('/cancel-order/<int:id>')
@login_required
def cancel_order(id):
    order = Order.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    if order.status == "Placed":
        order.status = "Cancelled"
        db.session.commit()
    return redirect(url_for('profile'))

@app.route('/request-return/<int:id>')
@login_required
def request_return(id):
    order = Order.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    order.status = "Return Requested"
    db.session.commit()
    return redirect(url_for('profile'))

@app.route('/admin')
@login_required
def admin_panel():
    if current_user.email != 'admin@test.gmail.com':
        return "Access Denied", 403
    all_orders = Order.query.order_by(Order.date_ordered.desc()).all()
    return render_template('admin.html', orders=all_orders)

# --- 8. RENDER PORT ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
