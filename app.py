import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'evia_secure_2025')

# --- DATABASE SETUP ---
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
    date_ordered = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- SHOP ROUTES ---
@app.route('/')
def index():
    return render_template('index.html', products=Product.query.all())

# --- AUTH ROUTES ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        if User.query.filter_by(email=email).first():
            flash("Email already exists!")
            return redirect(url_for('signup'))
        new_user = User(
            full_name=request.form.get('name'),
            email=email,
            password=generate_password_hash(request.form.get('password'), method='pbkdf2:sha256')
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
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
            if user.email == 'admin@test.gmail.com':
                flash("Welcome Boss! Admin Access Granted.")
                return redirect(url_for('admin_panel'))
            return redirect(url_for('index'))
            
        flash("Invalid email or password")
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- CART & BAG LOGIC ---
@app.route('/cart')
def cart():
    cart_ids = session.get('cart', [])
    items = Product.query.filter(Product.id.in_(cart_ids)).all() if cart_ids else []
    total = sum(i.price for i in items)
    return render_template('cart.html', items=items, total=total)

@app.route('/add-to-cart/<int:id>')
def add_to_cart(id):
    if 'cart' not in session:
        session['cart'] = []
    cart_list = session['cart']
    cart_list.append(id)
    session['cart'] = cart_list
    session.modified = True
    flash("Item added to your bag!")
    return redirect(url_for('index'))

@app.route('/remove-from-cart/<int:id>')
def remove_from_cart(id):
    cart_list = session.get('cart', [])
    if id in cart_list:
        cart_list.remove(id)
        session['cart'] = cart_list
        session.modified = True
        flash("Item removed from bag.")
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart_ids = session.get('cart', [])
    items = Product.query.filter(Product.id.in_(cart_ids)).all() if cart_ids else []
    
    if not items:
        flash("Your bag is empty!")
        return redirect(url_for('index'))

    total = sum(i.price for i in items)

    if request.method == 'POST':
        whatsapp = request.form.get('whatsapp')
        address = request.form.get('address')
        district = request.form.get('district')
        pincode = request.form.get('pincode')
        
        full_address = f"{address}, {district} - {pincode}"
        product_names = ", ".join([p.name for p in items])

        new_order = Order(
            product_details=product_names,
            total_price=total,
            user_id=current_user.id,
            whatsapp=whatsapp,
            address=full_address,
            status="Placed"
        )
        db.session.add(new_order)
        db.session.commit()
        session.pop('cart', None)
        return render_template('checkout.html', success=True)

    return render_template('checkout.html', total=total, items=items, success=False)

# --- ADMIN ROUTES ---
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if current_user.email != 'admin@test.gmail.com':
        return "<h1>Access Denied</h1><p>Only the owner can see this page.</p>", 403

    if request.method == 'POST':
        new_p = Product(
            name=request.form.get('name'), 
            price=request.form.get('price'),
            image=request.form.get('image'), 
            image_2=request.form.get('image_2'),
            description=request.form.get('description')
        )
        db.session.add(new_p)
        db.session.commit()
        flash("Product added successfully!")
        return redirect(url_for('admin_panel'))

    orders = Order.query.order_by(Order.date_ordered.desc()).all()
    return render_template('admin.html', orders=orders)

@app.route('/update_status/<int:id>/<string:st>')
@login_required
def update_status(id, st):
    if current_user.email == 'admin@test.gmail.com':
        o = Order.query.get(id)
        if o:
            o.status = st
            db.session.commit()
            flash(f"Order #{id} status updated!")
    return redirect(url_for('admin_panel'))

# --- SETUP ROUTE ---
@app.route('/setup-admin-99')
def setup_admin():
    db.drop_all()
    db.create_all()
    admin = User(
        full_name="Admin", 
        email="admin@test.gmail.com", 
        password=generate_password_hash('admin123', method='pbkdf2:sha256'), 
        is_admin=True
    )
    db.session.add(admin)
    db.session.commit()
    return "evia.db FIXED! Login: admin@test.gmail.com | Pass: admin123"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
