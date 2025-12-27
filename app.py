import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
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

@app.route('/cart')
def view_cart():
    cart_ids = session.get('cart', [])
    items = [Product.query.get(pid) for pid in cart_ids if Product.query.get(pid)]
    total = sum(item.price for item in items)
    return render_template('cart.html', items=items, total=total)

@app.route('/add_to_cart/<int:id>')
def add_to_cart(id):
    if 'cart' not in session: session['cart'] = []
    cart = list(session['cart'])
    cart.append(id)
    session['cart'] = cart
    session.modified = True
    flash("Added to bag")
    return redirect(url_for('view_cart'))

# --- CHECKOUT & ORDER LOGIC ---

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    # Logic to get items based on session mode (cart or single)
    items = []
    if session.get('checkout_mode') == 'cart':
        items = [Product.query.get(pid) for pid in session.get('cart', []) if Product.query.get(pid)]
    else:
        p = Product.query.get(session.get('single_id'))
        if p: items = [p]

    if not items: return redirect(url_for('index'))
    total = sum(i.price for i in items)

    if request.method == 'POST':
        cust_name = request.form.get('full_name')
        phone = request.form.get('phone')
        addr = f"{request.form.get('address')}, {request.form.get('district')}, {request.form.get('state')} - {request.form.get('pincode')}"
        item_names = ", ".join([i.name for i in items])
        
        new_order = Order(
            product_details=f"Items: {item_names} | Address: {addr} | Phone: {phone}",
            total_price=total,
            user_id=current_user.id
        )
        db.session.add(new_order)
        db.session.commit()
        
        # Clear cart if it was a cart checkout
        if session.get('checkout_mode') == 'cart': session.pop('cart', None)
        
        flash("Order Placed Successfully")
        return redirect(url_for('profile'))

    return render_template('checkout.html', product=items[0], total=total, items=items, count=len(items))

# --- PROFILE & ORDER ACTIONS (The missing fixes) ---

@app.route('/profile')
@login_required
def profile():
    # Fetch all orders for the current user
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.id.desc()).all()
    return render_template('profile.html', orders=orders)

@app.route('/cancel_order/<int:id>')
@login_required
def cancel_order(id):
    order = Order.query.get_or_404(id)
    # Security: Ensure the user only cancels their own order
    if order.user_id == current_user.id and order.status == "Placed":
        order.status = "Cancelled"
        db.session.commit()
        flash("Order Cancelled")
    return redirect(url_for('profile'))

@app.route('/return_order/<int:id>')
@login_required
def return_order(id):
    order = Order.query.get_or_404(id)
    if order.user_id == current_user.id and order.status == "Delivered":
        order.status = "Return Requested"
        db.session.commit()
        flash("Return request submitted")
    return redirect(url_for('profile'))

# --- AUTH & ADMIN ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))
        flash("Invalid Credentials")
    return render_template('login.html')

@app.route('/admin_lock', methods=['GET', 'POST'])
def admin_lock():
    if request.method == 'POST' and request.form.get('admin_pass') == ADMIN_SECRET_PASS:
        session['admin_verified'] = True
        return redirect(url_for('admin'))
    return render_template('admin_lock.html')

@app.route('/admin')
def admin():
    if not session.get('admin_verified'): return redirect(url_for('admin_lock'))
    return render_template('admin.html', products=Product.query.all(), orders=Order.query.all())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
