import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'evia_official_secure_key_2025'

# --- DATABASE ---
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
    product_details = db.Column(db.Text) # Stores product names/prices
    total_price = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    whatsapp = db.Column(db.String(20))
    address = db.Column(db.Text)
    # Status: Placed, Shipped, Out for Delivery, Delivered, Return Requested, Cancelled
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

@app.route('/product/<int:id>')
def product_detail(id):
    product = Product.query.get_or_404(id)
    return render_template('product_detail.html', product=product)

# --- CART SYSTEM ---
@app.route('/add-to-cart/<int:id>')
def add_to_cart(id):
    if 'cart' not in session: session['cart'] = []
    cart = list(session['cart'])
    cart.append(id)
    session['cart'] = cart
    session.modified = True
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest': return "OK", 200
    return redirect(url_for('cart'))

@app.route('/remove-from-cart/<int:id>')
def remove_from_cart(id):
    if 'cart' in session:
        cart = list(session['cart'])
        if id in cart:
            cart.remove(id)
            session['cart'] = cart
            session.modified = True
    return redirect(url_for('cart'))

@app.route('/cart')
def cart():
    cart_ids = session.get('cart', [])
    items = [Product.query.get(p_id) for p_id in cart_ids if Product.query.get(p_id)]
    total = sum(i.price for i in items)
    return render_template('cart.html', items=items, total=total)

# --- ORDERS & PROFILE ---
@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    cart_ids = session.get('cart', [])
    if not cart_ids: return redirect(url_for('index'))
    
    items = [Product.query.get(p_id) for p_id in cart_ids]
    details = ", ".join([p.name for p in items])
    total = sum(p.price for p in items)
    
    new_order = Order(
        product_details=details,
        total_price=total,
        user_id=current_user.id,
        whatsapp=request.form.get('whatsapp'),
        address=request.form.get('address'),
        status="Placed"
    )
    db.session.add(new_order)
    session.pop('cart', None)
    db.session.commit()
    return redirect(url_for('profile'))

@app.route('/profile')
@login_required
def profile():
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.date_ordered.desc()).all()
    return render_template('profile.html', orders=orders)

@app.route('/request-return/<int:id>')
@login_required
def request_return(id):
    order = Order.query.get_or_404(id)
    if order.user_id == current_user.id:
        order.status = "Return Requested"
        db.session.commit()
    return redirect(url_for('profile'))

# --- ADMIN PANEL ---
@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin: return "Access Denied", 403
    orders = Order.query.order_by(Order.date_ordered.desc()).all()
    products = Product.query.all()
    return render_template('admin.html', orders=orders, products=products)

@app.route('/admin/update-status/<int:id>/<string:status>')
@login_required
def update_status(id, status):
    if not current_user.is_admin: return "Denied", 403
    order = Order.query.get(id)
    order.status = status
    db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin/add-product', methods=['POST'])
@login_required
def add_product():
    new_p = Product(
        name=request.form.get('name'),
        price=int(request.form.get('price')),
        image=request.form.get('image'),
        image_2=request.form.get('image_2'),
        description=request.form.get('description')
    )
    db.session.add(new_p)
    db.session.commit()
    return redirect(url_for('admin_panel'))

if __name__ == '__main__':
    app.run(debug=True)
