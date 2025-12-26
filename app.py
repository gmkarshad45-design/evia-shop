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

ADMIN_SECRET_PASS = "razi1321"

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

# --- DATABASE INITIALIZATION ---
with app.app_context():
    db.create_all()
    print("🟢 Database & Columns Initialized.")

# --- MAIN ROUTES ---
@app.route('/')
def index():
    query = request.args.get('q')
    if query:
        # Search functionality for the search bar
        products = Product.query.filter(Product.name.contains(query)).all()
    else:
        products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/product/<int:id>')
def product_detail(id):
    product = Product.query.get_or_404(id)
    return render_template('product_detail.html', product=product)

@app.route('/buy/<int:id>')
@login_required
def buy_now(id):
    session['checkout_item'] = id
    return redirect(url_for('checkout'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    product_id = session.get('checkout_item')
    if not product_id:
        return redirect(url_for('index'))
    
    product = Product.query.get(product_id)
    
    if request.method == 'POST':
        phone = request.form.get('phone')
        addr = request.form.get('address')
        dist = request.form.get('district')
        pin = request.form.get('pincode')
        state = request.form.get('state')

        full_details = f"Product: {product.name} | WA: {phone} | Addr: {addr}, {dist}, {state} - {pin}"

        new_order = Order(
            product_details=full_details,
            total_price=product.price,
            user_id=current_user.id,
            status="Placed"
        )
        db.session.add(new_order)
        db.session.commit()
        
        flash("Success")
        return redirect(url_for('checkout'))
        
    return render_template('checkout.html', product=product)

# --- AUTH ROUTES ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('full_name')
        email = request.form.get('email')
        passwd = request.form.get('password')
        if User.query.filter_by(email=email).first():
            flash("Email already registered!")
            return redirect(url_for('signup'))
        new_user = User(full_name=name, email=email, password=generate_password_hash(passwd))
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
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- PROFILE & ORDER ACTIONS ---
@app.route('/profile')
@login_required
def profile():
    user_orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.id.desc()).all()
    return render_template('profile.html', orders=user_orders)

@app.route('/cancel_order/<int:id>')
@login_required
def cancel_order(id):
    order = Order.query.get_or_404(id)
    if order.user_id == current_user.id:
        order.status = "Cancelled"
        db.session.commit()
    return redirect(url_for('profile'))

@app.route('/return_order/<int:id>')
@login_required
def return_order(id):
    order = Order.query.get_or_404(id)
    if order.user_id == current_user.id:
        order.status = "Return Requested"
        db.session.commit()
    return redirect(url_for('profile'))

# --- ADMIN ROUTES ---
@app.route('/admin_lock', methods=['GET', 'POST'])
def admin_lock():
    if request.method == 'POST':
        if request.form.get('admin_pass') == ADMIN_SECRET_PASS:
            session['admin_verified'] = True
            return redirect(url_for('admin'))
    return render_template('admin_lock.html')

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_verified', None)
    return redirect(url_for('index'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get('admin_verified'):
        return redirect(url_for('admin_lock'))
    
    if request.method == 'POST':
        p = Product(
            name=request.form.get('name'), 
            price=int(request.form.get('price')), 
            image=request.form.get('image_url'),
            description=request.form.get('description')
        )
        db.session.add(p)
        db.session.commit()
        return redirect(url_for('admin'))
    
    products = Product.query.all()
    orders = Order.query.all()
    return render_template('admin.html', products=products, orders=orders)

@app.route('/admin/update_status/<int:id>/<string:new_status>')
def update_order_status(id, new_status):
    if not session.get('admin_verified'): return redirect(url_for('admin_lock'))
    order = Order.query.get_or_404(id)
    order.status = new_status
    db.session.commit()
    return redirect(url_for('admin'))

@app.route('/delete/<int:id>')
def delete_product(id):
    if not session.get('admin_verified'): return redirect(url_for('admin_lock'))
    p = Product.query.get_or_404(id)
    db.session.delete(p)
    db.session.commit()
    return redirect(url_for('admin'))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
