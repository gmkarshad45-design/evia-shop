import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'evia_pro_2025_secure_key'

# --- PRO DATABASE SETUP ---
database_url = os.getenv("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///evia_pro.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

ADMIN_PASS = "evia54321"

# --- PRO MODELS ---
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
    stock = db.Column(db.Integer, default=10) # Inventory tracking
    category = db.Column(db.String(50))

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_details = db.Column(db.Text) 
    total_price = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(50), default="Placed")
    created_at = db.Column(db.DateTime, default=datetime.utcnow) # Pro tracking

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- DATA INITIALIZATION ---
with app.app_context():
    db.create_all()
    # Optional: Seed data if empty
    if not Product.query.first():
        p = Product(name="Pro Example", price=499, description="High quality item", category="Premium")
        db.session.add(p)
        db.session.commit()

# --- ROUTES ---

@app.route('/')
def index():
    query = request.args.get('q')
    products = Product.query.filter(Product.name.contains(query)).all() if query else Product.query.all()
    return render_template('index.html', products=products)

@app.route('/buy_now/<int:id>')
@login_required
def buy_now(id):
    session['checkout_mode'] = 'single'
    session['single_id'] = id
    return redirect(url_for('checkout'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    items = []
    if session.get('checkout_mode') == 'cart':
        items = [Product.query.get(pid) for pid in session.get('cart', []) if Product.query.get(pid)]
    else:
        p = Product.query.get(session.get('single_id'))
        if p: items = [p]

    if not items: return redirect(url_for('index'))
    total = sum(i.price for i in items)

    if request.method == 'POST':
        # Stock Check Logic
        for item in items:
            if item.stock <= 0:
                flash(f"Sorry, {item.name} is out of stock.")
                return redirect(url_for('view_cart'))
            item.stock -= 1 # Decrease inventory

        new_order = Order(
            product_details=f"Items: {', '.join([i.name for i in items])} | Address: {request.form.get('address')}",
            total_price=total,
            user_id=current_user.id
        )
        db.session.add(new_order)
        db.session.commit()
        
        if session.get('checkout_mode') == 'cart': session.pop('cart', None)
        flash("Order placed successfully!")
        return redirect(url_for('profile'))

    return render_template('checkout.html', items=items, total=total, count=len(items))

# --- PRO ADMIN & ANALYTICS ---

@app.route('/admin')
def admin():
    if not session.get('admin_verified'): return redirect(url_for('admin_lock'))
    
    orders = Order.query.order_by(Order.id.desc()).all()
    # Calculate Total Pro Revenue
    revenue = sum(o.total_price for o in orders if o.status != "Cancelled")
    
    return render_template('admin.html', products=Product.query.all(), orders=orders, revenue=revenue)

@app.route('/admin/update_status/<int:id>/<string:new_status>')
def update_order_status(id, new_status):
    if not session.get('admin_verified'): return redirect(url_for('admin_lock'))
    order = Order.query.get_or_404(id)
    order.status = new_status
    db.session.commit()
    flash(f"Order #{id} updated to {new_status}")
    return redirect(url_for('admin'))

# Auth logic (Login/Signup/Logout/AdminLock) goes here...

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
