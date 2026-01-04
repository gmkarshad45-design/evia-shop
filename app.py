import os
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'evia_official_secure_2025'

# --- DATABASE CONFIG ---
database_url = os.environ.get("DATABASE_URL", "sqlite:///evia.db")
if database_url and database_url.startswith("postgres://"):
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
    status = db.Column(db.String(50), default="Placed") 
    date_ordered = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- SHOP & SEARCH ---
@app.route('/')
def index():
    q = request.args.get('q')
    if q:
        products = Product.query.filter(Product.name.icontains(q)).all()
    else:
        products = Product.query.all()
    return render_template('index.html', products=products)

# --- CART SYSTEM ---
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
    return redirect(url_for('cart'))

@app.route('/remove-from-cart/<int:id>')
def remove_from_cart(id):
    if 'cart' in session:
        cart = list(session['cart'])
        if id in cart: cart.remove(id)
        session['cart'] = cart
        session.modified = True
    return redirect(url_for('cart'))

@app.route('/cart')
def cart():
    cart_ids = session.get('cart', [])
    items = [Product.query.get(p_id) for p_id in cart_ids if Product.query.get(p_id)]
    total = sum(i.price for i in items)
    return render_template('cart.html', items=items, total=total)

# --- CHECKOUT LOGIC ---
@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    cart_ids = session.get('cart', [])
    if not cart_ids: return redirect(url_for('index'))
    
    items = [Product.query.get(p_id) for p_id in cart_ids if Product.query.get(p_id)]
    details = ", ".join([f"{i.name} (₹{i.price})" for i in items])
    total = sum(i.price for i in items)
    
    order = Order(
        product_details=details,
        total_price=total,
        user_id=current_user.id,
        whatsapp=request.form.get('whatsapp'),
        address=request.form.get('address')
    )
    db.session.add(order)
    db.session.commit()
    
    session.pop('cart', None)
    # Redirect to a success page with order details
    return render_template('checkout.html', order=order)

@app.route('/profile')
@login_required
def profile():
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.date_ordered.desc()).all()
    return render_template('profile.html', orders=orders)

# --- ADMIN PANEL ---
@app.route('/admin')
@login_required
def admin_panel():
    if current_user.email != 'admin@test.gmail.com': return "Denied", 403
    orders = Order.query.order_by(Order.date_ordered.desc()).all()
    products = Product.query.all()
    revenue = sum(o.total_price for o in orders if o.status != 'Cancelled')
    return render_template('admin.html', orders=orders, products=products, revenue=revenue)

@app.route('/admin/delete-product/<int:id>')
@login_required
def delete_product(id):
    if current_user.email != 'admin@test.gmail.com': return "Denied", 403
    p = Product.query.get(id)
    if p:
        db.session.delete(p)
        db.session.commit()
    return redirect(url_for('admin_panel'))

# --- AUTH ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('admin_panel' if user.email == 'admin@test.gmail.com' else 'index'))
    return render_template('login.html')

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

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/setup')
def setup():
    db.create_all()
    if not User.query.filter_by(email='admin@test.gmail.com').first():
        admin = User(full_name="Admin", email="admin@test.gmail.com", 
                     password=generate_password_hash('admin123', method='pbkdf2:sha256'), is_admin=True)
        db.session.add(admin)
        db.session.commit()
    return "Ready!"

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=True, host='0.0.0.0', port=10000)
