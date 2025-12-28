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

# Initialize database
with app.app_context():
    db.create_all()

# --- MAIN SHOP ROUTES ---

@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/product/<int:id>')
def product_detail(id):
    """ FIX: Added to resolve BuildError for 'product_detail' """
    product = Product.query.get_or_404(id)
    return render_template('product_detail.html', product=product)

@app.route('/add_to_cart/<int:id>')
def add_to_cart(id):
    """ FIX: Added to resolve BuildError for 'add_to_cart' """
    if 'cart' not in session:
        session['cart'] = []
    
    cart = session['cart']
    cart.append(id)
    session['cart'] = cart
    
    flash("Item added to cart!")
    return redirect(url_for('index'))

@app.route('/cart')
def cart():
    cart_ids = session.get('cart', [])
    products = Product.query.filter(Product.id.in_(cart_ids)).all() if cart_ids else []
    return render_template('cart.html', products=products)

@app.route('/remove_from_cart/<int:id>')
def remove_from_cart(id):
    cart = session.get('cart', [])
    if id in cart:
        cart.remove(id)
        session['cart'] = cart
    return redirect(url_for('cart'))

# --- USER & ACCOUNT ROUTES ---

@app.route('/profile')
@login_required
def profile():
    user_orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.id.desc()).all()
    return render_template('profile.html', orders=user_orders)

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart_ids = session.get('cart', [])
    items = Product.query.filter(Product.id.in_(cart_ids)).all() if cart_ids else []
    
    if not items:
        flash("Your cart is empty!")
        return redirect(url_for('index'))

    total = sum(i.price for i in items)

    if request.method == 'POST':
        addr = f"{request.form.get('address')}, {request.form.get('district')}, {request.form.get('state')} - {request.form.get('pincode')}"
        new_order = Order(
            product_details=f"Items: {', '.join([i.name for i in items])} | Addr: {addr} | WA: {request.form.get('phone')}",
            total_price=total,
            user_id=current_user.id
        )
        db.session.add(new_order)
        db.session.commit()
        session.pop('cart', None)
        flash("ORDER_SUCCESS") 
        return redirect(url_for('profile'))

    return render_template('checkout.html', total=total, items=items)

# --- AUTH ROUTES ---

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256')
        new_user = User(
            full_name=request.form.get('full_name'), 
            email=request.form.get('email'), 
            password=hashed_pw
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))
        flash("Invalid Credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- ORDER ACTIONS ---

@app.route('/cancel_order/<int:id>')
@login_required
def cancel_order(id):
    order = Order.query.get_or_404(id)
    if order.user_id == current_user.id:
        order.status = "Cancelled"
        db.session.commit()
    return redirect(url_for('profile'))

@app.route('/init-db')
def init_db():
    """ Use this once on Render to setup your Postgres tables """
    db.create_all()
    return "Tables Created!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
