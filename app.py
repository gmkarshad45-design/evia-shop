import os
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text 

app = Flask(__name__)

# --- 1. CONFIGURATION ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'evia_final_secret_2026')
# Updated database name for your new deployment
database_url = os.environ.get("DATABASE_URL", "sqlite:///evia1_db.db")

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
    image_2 = db.Column(db.String(500)) 
    description = db.Column(db.Text)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_details = db.Column(db.Text)
    total_price = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(50), default="Placed")
    address = db.Column(db.Text)
    whatsapp = db.Column(db.String(20))
    date_ordered = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- DATABASE INITIALIZATION ---
with app.app_context():
    db.create_all()
    try:
        db.session.execute(text('SELECT image_2 FROM product LIMIT 1'))
    except Exception:
        db.session.execute(text('ALTER TABLE product ADD COLUMN image_2 VARCHAR(500)'))
        db.session.commit()

# --- 3. MAIN ROUTES ---
@app.route('/')
def index():
    query = request.args.get('q') 
    if query:
        products = Product.query.filter(Product.name.ilike(f'%{query}%')).all()
    else:
        products = Product.query.all()
    
    cart = session.get('cart', [])
    return render_template('index.html', products=products, cart_count=len(cart))

@app.route('/product/<int:id>')
def product_detail(id):
    product = db.session.get(Product, id)
    if not product:
        flash("Product not found")
        return redirect(url_for('index'))
    return render_template('product_detail.html', product=product)

# --- 4. CART LOGIC ---
@app.route('/add-to-cart/<int:id>')
def add_to_cart(id):
    if 'cart' not in session or not isinstance(session['cart'], list):
        session['cart'] = []
    cart = list(session['cart'])
    cart.append(id)
    session['cart'] = cart
    session.modified = True 
    flash("Added to bag")
    return redirect(url_for('index'))

@app.route('/cart')
def cart_view():
    cart_ids = session.get('cart', [])
    items = [db.session.get(Product, p_id) for p_id in cart_ids if db.session.get(Product, p_id)]
    total = sum(i.price for i in items)
    return render_template('cart.html', items=items, total=total)

# --- 5. CHECKOUT ---
@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    cart_ids = session.get('cart', [])
    if not cart_ids: return redirect(url_for('index'))
    
    user_address = request.form.get('address')
    user_whatsapp = request.form.get('whatsapp')
    
    items = [db.session.get(Product, p_id) for p_id in cart_ids if db.session.get(Product, p_id)]
    details = ", ".join([p.name for p in items])
    total = sum(p.price for p in items)
    
    new_order = Order(product_details=details, total_price=total, user_id=current_user.id, address=user_address, whatsapp=user_whatsapp)
    db.session.add(new_order)
    db.session.commit()
    session.pop('cart', None)
    return redirect(url_for('profile'))

# --- 6. USER PROFILE ---
@app.route('/profile')
@login_required
def profile():
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.date_ordered.desc()).all()
    return render_template('profile.html', orders=orders)

# --- 7. ADMIN PANEL ---
@app.route('/admin') # This route was missing in your draft!
@login_required
def admin_panel():
    # SET TO YOUR ADMIN EMAIL
    if current_user.email != 'evia@test.gmail.com': 
        return "Denied", 403
    orders = Order.query.order_by(Order.date_ordered.desc()).all()
    products = Product.query.all() 
    return render_template('admin.html', orders=orders, products=products)

@app.route('/admin/add-product', methods=['POST'])
@login_required
def add_product():
    if current_user.email != 'evia@test.gmail.com': return "Denied", 403
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

@app.route('/admin/delete-product/<int:id>')
@login_required
def delete_product(id):
    if current_user.email != 'evia@test.gmail.com': return "Denied", 403
    p = db.session.get(Product, id)
    if p:
        db.session.delete(p)
        db.session.commit()
    return redirect(url_for('admin_panel'))

# --- 8. AUTHENTICATION (THE GHOST FIX) ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email').lower().strip()
        if User.query.filter_by(email=email).first():
            return redirect(url_for('login'))
        
        new_user = User(
            full_name=request.form.get('full_name'), 
            email=email, 
            password=generate_password_hash(request.form.get('password'))
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('index'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').lower().strip()
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user, remember=True)
            return redirect(url_for('index'))
        flash("Invalid Credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
