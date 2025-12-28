import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'evia_production_secret_9988'

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
    image_2 = db.Column(db.String(500))
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

# --- HOME & PRODUCT ROUTES ---
@app.route('/')
def index():
    q = request.args.get('q')
    products = Product.query.filter(Product.name.contains(q)).all() if q else Product.query.all()
    return render_template('index.html', products=products)

@app.route('/product/<int:id>')
def product_detail(id):
    product = Product.query.get_or_404(id)
    return render_template('product_detail.html', product=product)

# --- CART & CHECKOUT ---
@app.route('/cart')
def cart():
    cart_ids = session.get('cart', [])
    products = [Product.query.get(pid) for pid in cart_ids if Product.query.get(pid)]
    total = sum(p.price for p in products)
    return render_template('cart.html', products=products, total=total)

@app.route('/add_to_cart/<int:id>')
def add_to_cart(id):
    if 'cart' not in session: session['cart'] = []
    cart_list = list(session['cart'])
    cart_list.append(id)
    session['cart'] = cart_list
    session.modified = True
    flash("Item added to bag!")
    return redirect(request.referrer or url_for('index'))

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
    if not cart_ids: return redirect(url_for('index'))
    
    products = [Product.query.get(pid) for pid in cart_ids if Product.query.get(pid)]
    total = sum(p.price for p in products)

    if request.method == 'POST':
        details = ", ".join([p.name for p in products])
        order = Order(product_details=details, total_price=total, user_id=current_user.id)
        db.session.add(order)
        db.session.commit()
        session.pop('cart', None)
        return redirect(url_for('profile'))
        
    return render_template('checkout.html', products=products, total=total)

# --- USER AUTH & PROFILE ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form.get('name'), method='pbkdf2:sha256')
        user = User(full_name=request.form.get('name'), email=request.form.get('email'), password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('index'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('admin_panel' if user.is_admin else 'index'))
        flash("Invalid Credentials")
    return render_template('login.html')

@app.route('/profile')
@login_required
def profile():
    orders = Order.query.filter_by(user_id=current_user.id).all()
    return render_template('profile.html', orders=orders)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- ADMIN PANEL ---
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if not current_user.is_admin: return render_template('admin_lock.html')
    if request.method == 'POST':
        p = Product(name=request.form.get('name'), price=int(request.form.get('price')),
                    image=request.form.get('image'), description=request.form.get('description'))
        db.session.add(p)
        db.session.commit()
    return render_template('admin.html', products=Product.query.all())

@app.route('/admin/delete/<int:id>')
@login_required
def admin_delete(id):
    if current_user.is_admin:
        p = Product.query.get(id)
        db.session.delete(p)
        db.session.commit()
    return redirect(url_for('admin_panel'))

# --- DB INIT ---
@app.route('/init-db')
def init_db():
    db.create_all()
    if not User.query.filter_by(email="admin@evia.com").first():
        admin = User(full_name="Admin", email="admin@evia.com", 
                     password=generate_password_hash("admin123", method='pbkdf2:sha256'), is_admin=True)
        db.session.add(admin)
        db.session.commit()
    return "Database Ready"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
