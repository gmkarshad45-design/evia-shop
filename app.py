import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'evia_official_premium_2025'

# --- DATABASE SETUP ---
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///evia_shop.db'
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

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Fix: Check for both possible names from your HTML files
        name = request.form.get('name') or request.form.get('full_name')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(email=email).first():
            flash("Email already registered.")
            return redirect(url_for('signup'))

        user = User(
            full_name=name, 
            email=email, 
            password=generate_password_hash(password, method='pbkdf2:sha256')
        )
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('index'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin_panel') if user.is_admin else url_for('index'))
        flash("Invalid credentials.")
    return render_template('login.html')

@app.route('/cart')
def cart():
    cart_ids = session.get('cart', [])
    products = [Product.query.get(pid) for pid in cart_ids if Product.query.get(pid)]
    total = sum(p.price for p in products)
    return render_template('cart.html', products=products, total=total)

@app.route('/add_to_cart/<int:id>')
def add_to_cart(id):
    if 'cart' not in session:
        session['cart'] = []
    cart_list = list(session['cart'])
    cart_list.append(id)
    session['cart'] = cart_list
    session.modified = True
    return redirect(url_for('cart'))

@app.route('/delete_cart_item/<int:id>')
def delete_cart_item(id):
    if 'cart' in session:
        cart_list = list(session['cart'])
        if id in cart_list:
            cart_list.remove(id)
            session['cart'] = cart_list
            session.modified = True
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart_ids = session.get('cart', [])
    if not cart_ids:
        return redirect(url_for('index'))
    
    products = [Product.query.get(pid) for pid in cart_ids if Product.query.get(pid)]
    total = sum(p.price for p in products)

    if request.method == 'POST':
        # Create the order record
        details = ", ".join([p.name for p in products])
        new_order = Order(
            product_details=details, 
            total_price=total, 
            user_id=current_user.id
        )
        db.session.add(new_order)
        db.session.commit()
        
        # Clear cart and send to profile
        session.pop('cart', None)
        flash("Order placed successfully!")
        return redirect(url_for('profile'))
        
    return render_template('checkout.html', products=products, total=total)

@app.route('/profile')
@login_required
def profile():
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.date_ordered.desc()).all()
    return render_template('profile.html', orders=orders)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if not current_user.is_admin:
        return render_template('admin_lock.html')
    if request.method == 'POST':
        p = Product(
            name=request.form.get('name'), 
            price=int(request.form.get('price')),
            image=request.form.get('image'), 
            description=request.form.get('description')
        )
        db.session.add(p)
        db.session.commit()
        flash("Product added!")
    return render_template('admin.html', products=Product.query.all())

@app.route('/init-db')
def init_db():
    db.create_all()
    if not User.query.filter_by(email="admin@test.com").first():
        admin = User(
            full_name="Admin", 
            email="admin@test.com", 
            password=generate_password_hash("admin123", method='pbkdf2:sha256'), 
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
    return "Success: Database and Admin account (admin@test.com) are ready."

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
