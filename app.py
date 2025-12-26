import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'evia_shop_secure_key_1321'

# --- DATABASE CONFIGURATION ---
# Handles Render Postgres (Singapore) and Local SQLite fallback
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

# --- MAIN ROUTES ---
@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products)

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
        flash("Registration Successful! Please Login.")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))
        flash("Invalid Email or Password")
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- ADMIN PANEL ROUTES ---
@app.route('/admin_lock', methods=['GET', 'POST'])
def admin_lock():
    if request.method == 'POST':
        if request.form.get('admin_pass') == ADMIN_SECRET_PASS:
            session['admin_verified'] = True
            return redirect(url_for('admin'))
        flash("Incorrect Master Key!")
    return render_template('admin_lock.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get('admin_verified'):
        return redirect(url_for('admin_lock'))

    if request.method == 'POST':
        try:
            p = Product(
                name=request.form.get('name'), 
                price=int(request.form.get('price')), 
                stock=int(request.form.get('stock')), 
                category=request.form.get('category'), 
                description=request.form.get('description'),
                image=request.form.get('image_url'),
                image_2=request.form.get('image_url_2')
            )
            db.session.add(p)
            db.session.commit()
            flash("Product published successfully!")
        except Exception as e:
            db.session.rollback()
            flash(f"Error: {str(e)}")
        return redirect(url_for('admin'))
    
    products = Product.query.all()
    orders = Order.query.order_by(Order.id.desc()).all() 
    return render_template('admin.html', products=products, orders=orders)

@app.route('/delete/<int:id>')
def delete_product(id):
    if not session.get('admin_verified'):
        return redirect(url_for('admin_lock'))
    p = Product.query.get_or_404(id)
    db.session.delete(p)
    db.session.commit()
    flash("Item removed from Inventory.")
    return redirect(url_for('admin'))

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_verified', None)
    return redirect(url_for('index'))

# --- RENDER PORT BINDING ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
