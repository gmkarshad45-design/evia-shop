import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Keep this secret key fixed so sessions/carts don't reset
app.config['SECRET_KEY'] = 'evia_clothing_final_fix_2025'

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
@app.route('/add_to_cart/<int:id>')
def add_to_cart(id):
    if 'cart' not in session:
        session['cart'] = []
    cart_list = list(session.get('cart', []))
    cart_list.append(id)
    session['cart'] = cart_list
    session.modified = True  # CRITICAL: Ensures the cart is saved
    flash("Product added to cart!")
    return redirect(url_for('index'))

@app.route('/cart')
def cart():
    cart_ids = session.get('cart', [])
    products_in_cart = [Product.query.get(p_id) for p_id in cart_ids if Product.query.get(p_id)]
    total = sum(p.price for p in products_in_cart)
    return render_template('cart.html', products=products_in_cart, total=total)

# --- ADMIN PANEL (Function admin_panel uses admin.html) ---
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        new_p = Product(
            name=request.form.get('name'),
            price=int(request.form.get('price')),
            description=request.form.get('description'),
            image=request.form.get('image')
        )
        db.session.add(new_p)
        db.session.commit()
        return redirect(url_for('admin_panel'))

    orders = Order.query.order_by(Order.id.desc()).all()
    products = Product.query.all()
    # This specifically looks for admin.html in your GitHub templates folder
    return render_template('admin.html', orders=orders, products=products)

@app.route('/admin/delete/<int:id>')
@login_required
def delete_product(id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    p = Product.query.get_or_404(id)
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
            # Redirects admin to the admin function, everyone else to home
            return redirect(url_for('admin_panel' if user.is_admin else 'index'))
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256')
        new_user = User(
            full_name=request.form.get('full_name'),
            email=request.form.get('email'),
            password=hashed_pw,
            is_admin=False
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('index'))
    return render_template('signup.html')

# --- THE DATABASE INITIALIZER (RUN THIS FIRST) ---
@app.route('/init-db')
def init_db():
    try:
        db.drop_all()
        db.create_all()
        admin_pw = generate_password_hash('admin123', method='pbkdf2:sha256')
        admin = User(full_name="Admin", email="admin@test.com", password=admin_pw, is_admin=True)
        db.session.add(admin)
        db.session.commit()
        return "Database Fix Success! Login: admin@test.com | Password: admin123"
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
