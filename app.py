import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'evia_clothing_2025_secure_key'

# --- DATABASE CONFIG ---
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
    full_name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(500))    # Primary Image
    image_2 = db.Column(db.String(500))  # Secondary Image
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

# --- SHOP ROUTES ---
@app.route('/')
def index():
    query = request.args.get('q')
    if query:
        products = Product.query.filter(Product.name.contains(query)).all()
    else:
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
    temp_cart = list(session['cart'])
    temp_cart.append(id)
    session['cart'] = temp_cart
    session.modified = True 
    flash("Added to bag!")
    return redirect(request.referrer or url_for('index'))

@app.route('/cart')
def cart():
    cart_ids = session.get('cart', [])
    # Get products and filter out any that might have been deleted from DB
    products_in_cart = [Product.query.get(p_id) for p_id in cart_ids if Product.query.get(p_id)]
    total = sum(p.price for p in products_in_cart)
    return render_template('cart.html', products=products_in_cart, total=total)

@app.route('/delete_cart_item/<int:id>')
def delete_cart_item(id):
    if 'cart' in session:
        temp_cart = list(session['cart'])
        if id in temp_cart:
            temp_cart.remove(id)
            session['cart'] = temp_cart
            session.modified = True
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    cart_ids = session.get('cart', [])
    if not cart_ids:
        return redirect(url_for('index'))
    products = [Product.query.get(p_id) for p_id in cart_ids if Product.query.get(p_id)]
    details = ", ".join([p.name for p in products])
    total = sum(p.price for p in products)
    new_order = Order(product_details=details, total_price=total, user_id=current_user.id)
    db.session.add(new_order)
    db.session.commit()
    session.pop('cart', None)
    return "Order Placed Successfully! <a href='/'>Go Home</a>"

# --- ADMIN ROUTES ---
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    if request.method == 'POST':
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
    products = Product.query.all()
    return render_template('admin.html', products=products)

@app.route('/admin/delete/<int:id>')
@login_required
def admin_delete_product(id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    product = Product.query.get_or_404(id)
    db.session.delete(product)
    db.session.commit()
    return redirect(url_for('admin_panel'))

# --- AUTH ROUTES ---
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

@app.route('/init-db')
def init_db():
    db.create_all()
    # Check if admin exists, if not create one
    if not User.query.filter_by(email="admin@test.com").first():
        admin_pw = generate_password_hash('admin123', method='pbkdf2:sha256')
        admin = User(full_name="Admin", email="admin@test.com", password=admin_pw, is_admin=True)
        db.session.add(admin)
        db.session.commit()
    return "DB Initialized. Login: admin@test.com / admin123"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
