import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Secret key is REQUIRED for the cart session to save
app.config['SECRET_KEY'] = 'evia_pro_ultra_secret_key_2025'

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
    stock = db.Column(db.Integer, default=10)

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

# --- ROUTES ---

@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products)

# --- FIXED CART LOGIC ---
@app.route('/add_to_cart/<int:id>')
def add_to_cart(id):
    if 'cart' not in session:
        session['cart'] = []
    
    # We must re-assign to session to ensure Flask marks it as "modified"
    cart_list = list(session['cart'])
    cart_list.append(id)
    session['cart'] = cart_list
    session.modified = True 
    
    flash("Product added to cart!")
    return redirect(url_for('index'))

@app.route('/cart')
def cart():
    cart_ids = session.get('cart', [])
    products_in_cart = []
    total = 0
    
    # Loop through IDs to allow duplicate items and calculate total correctly
    for p_id in cart_ids:
        product = Product.query.get(p_id)
        if product:
            products_in_cart.append(product)
            total += product.price
            
    return render_template('cart.html', products=products_in_cart, total=total)

@app.route('/clear_cart')
def clear_cart():
    session.pop('cart', None)
    return redirect(url_for('cart'))

# --- FIXED ADMIN PANEL ROUTE ---
@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash("Unauthorized access!")
        return redirect(url_for('index'))
    
    orders = Order.query.order_by(Order.id.desc()).all()
    products = Product.query.all()
    users = User.query.all()
    return render_template('admin.html', orders=orders, products=products, users=users)

@app.route('/admin/update_order/<int:id>/<string:status>')
@login_required
def update_order(id, status):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    order = Order.query.get_or_404(id)
    order.status = status
    db.session.commit()
    flash(f"Order #{id} updated to {status}")
    return redirect(url_for('admin_panel'))

# --- CHECKOUT & PROFILE ---
@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    cart_ids = session.get('cart', [])
    if not cart_ids:
        return redirect(url_for('index'))

    items = [Product.query.get(p_id) for p_id in cart_ids if Product.query.get(p_id)]
    item_names = ", ".join([i.name for i in items])
    total = sum(i.price for i in items)

    new_order = Order(
        product_details=item_names,
        total_price=total,
        user_id=current_user.id,
        status="Placed"
    )
    db.session.add(new_order)
    db.session.commit()
    session.pop('cart', None) 
    return redirect(url_for('profile'))

@app.route('/profile')
@login_required
def profile():
    user_orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.id.desc()).all()
    return render_template('profile.html', orders=user_orders)

# --- AUTH ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('admin_panel' if user.is_admin else 'index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- INITIALIZE DATABASE ---
@app.route('/init-db')
def init_db():
    db.drop_all()
    db.create_all()
    
    # Create Admin
    admin_pw = generate_password_hash('admin123', method='pbkdf2:sha256')
    admin = User(full_name="Admin User", email="admin@test.com", password=admin_pw, is_admin=True)
    
    # Create Test Product
    p1 = Product(name="Sample Watch", price=1500, description="Elegant timepiece", image="")
    
    db.session.add(admin)
    db.session.add(p1)
    db.session.commit()
    return "Database Rebuilt! Admin Login: admin@test.com | Password: admin123"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
