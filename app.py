import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'evia_shop_secure_key_1321'

# --- DATABASE CONFIGURATION ---
database_url = os.getenv("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

ADMIN_SECRET_PASS = "evia54321"

# --- SQL MODELS ---
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
    image_2 = db.Column(db.String(500)) 
    description = db.Column(db.Text)    
    stock = db.Column(db.Integer, default=10)
    category = db.Column(db.String(50))

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_details = db.Column(db.Text) 
    total_price = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(50), default="Placed")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

# --- SHOPPING ROUTES ---

@app.route('/')
def index():
    query = request.args.get('q')
    products = Product.query.filter(Product.name.contains(query)).all() if query else Product.query.all()
    return render_template('index.html', products=products)

@app.route('/product/<int:id>')
def product_detail(id):
    product = Product.query.get_or_404(id)
    return render_template('product_detail.html', product=product)

@app.route('/add_to_cart/<int:id>')
def add_to_cart(id):
    if 'cart' not in session:
        session['cart'] = []
    temp_cart = list(session['cart'])
    temp_cart.append(id)
    session['cart'] = temp_cart
    session.modified = True 
    flash("Added to bag")
    return redirect(request.referrer or url_for('index'))

@app.route('/remove_from_cart/<int:id>')
def remove_from_cart(id):
    if 'cart' in session:
        temp_cart = list(session['cart'])
        if id in temp_cart:
            temp_cart.remove(id)
            session['cart'] = temp_cart
            session.modified = True
            flash("Item removed")
    return redirect(url_for('view_cart'))

@app.route('/cart')
def view_cart():
    if 'cart' not in session or not session['cart']:
        return render_template('cart.html', items=[], total=0)
    cart_items = []
    total_price = 0
    for pid in session['cart']:
        product = Product.query.get(pid)
        if product:
            cart_items.append(product)
            total_price += product.price
    return render_template('cart.html', items=cart_items, total=total_price)

# --- CHECKOUT LOGIC ---

@app.route('/buy/<int:id>')
@login_required
def buy_now(id):
    session.pop('cart_checkout', None)
    session['checkout_item'] = id
    return redirect(url_for('checkout'))

@app.route('/checkout_cart')
@login_required
def checkout_cart():
    if 'cart' not in session or not session['cart']:
        flash("Bag is empty")
        return redirect(url_for('index'))
    session.pop('checkout_item', None)
    session['cart_checkout'] = True
    return redirect(url_for('checkout'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    items_to_buy = []
    total_price = 0
    
    if session.get('cart_checkout'):
        for pid in session.get('cart', []):
            p = Product.query.get(pid)
            if p:
                items_to_buy.append(p)
                total_price += p.price
    else:
        pid = session.get('checkout_item')
        p = Product.query.get(pid) if pid else None
        if p:
            items_to_buy.append(p)
            total_price = p.price

    if not items_to_buy:
        return redirect(url_for('index'))

    if request.method == 'POST':
        cust_name = request.form.get('full_name')
        phone = request.form.get('phone')
        item_names = ", ".join([i.name for i in items_to_buy])
        addr = f"{request.form.get('address')}, {request.form.get('district')}, {request.form.get('state')} - {request.form.get('pincode')}"
        
        new_order = Order(
            product_details=f"NAME: {cust_name} | WA: {phone} | ITEMS: {item_names} | ADDR: {addr}",
            total_price=total_price,
            user_id=current_user.id
        )
        db.session.add(new_order)
        db.session.commit()
        
        session.pop('cart', None)
        session.pop('checkout_item', None)
        session.pop('cart_checkout', None)
        flash("Order Placed Successfully")
        return redirect(url_for('checkout'))

    return render_template('checkout.html', product=items_to_buy[0], total=total_price, count=len(items_to_buy))

# --- AUTH & ADMIN ---

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256')
        new_user = User(full_name=request.form.get('full_name'), email=request.form.get('email'), password=hashed_pw)
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        except:
            flash("Email already exists")
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

@app.route('/profile')
@login_required
def profile():
    user_orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.id.desc()).all()
    return render_template('profile.html', orders=user_orders)

@app.route('/admin_lock', methods=['GET', 'POST'])
def admin_lock():
    if request.method == 'POST' and request.form.get('admin_pass') == ADMIN_SECRET_PASS:
        session['admin_verified'] = True
        return redirect(url_for('admin'))
    return render_template('admin_lock.html')

@app.route('/admin')
def admin():
    if not session.get('admin_verified'): return redirect(url_for('admin_lock'))
    products = Product.query.all()
    orders = Order.query.order_by(Order.id.desc()).all()
    return render_template('admin.html', products=products, orders=orders)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
