import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'evia_official_2025'

# Database
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///evia_db.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(500))
    is_admin = db.Column(db.Boolean, default=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(500))
    image_2 = db.Column(db.String(500))
    description = db.Column(db.Text)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---

@app.route('/')
def index():
    q = request.args.get('q')
    products = Product.query.filter(Product.name.contains(q)).all() if q else Product.query.all()
    return render_template('index.html', products=products)

@app.route('/product/<int:id>')
def product_detail(id):
    product = Product.query.get_or_404(id)
    return render_template('product_detail.html', product=product)

# FIXED: ADD TO CART ROUTE
@app.route('/add_to_cart/<int:id>')
def add_to_cart(id):
    if 'cart' not in session:
        session['cart'] = []
    cart = list(session['cart'])
    cart.append(id)
    session['cart'] = cart
    session.modified = True
    flash("Added to bag!")
    return redirect(request.referrer or url_for('index'))

# FIXED: CART VIEW ROUTE
@app.route('/cart')
def cart():
    cart_ids = session.get('cart', [])
    products = [Product.query.get(p_id) for p_id in cart_ids if Product.query.get(p_id)]
    total = sum(p.price for p in products)
    return render_template('cart.html', products=products, total=total)

# FIXED: DELETE FROM CART ROUTE
@app.route('/delete_cart_item/<int:id>')
def delete_cart_item(id):
    if 'cart' in session:
        cart = list(session['cart'])
        if id in cart:
            cart.remove(id)
            session['cart'] = cart
            session.modified = True
    return redirect(url_for('cart'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if not current_user.is_admin: return redirect(url_for('index'))
    if request.method == 'POST':
        new_p = Product(name=request.form.get('name'), price=int(request.form.get('price')),
                        image=request.form.get('image'), image_2=request.form.get('image_2'),
                        description=request.form.get('description'))
        db.session.add(new_p)
        db.session.commit()
        return redirect(url_for('admin_panel'))
    products = Product.query.all()
    return render_template('admin.html', products=products)

@app.route('/admin/delete/<int:id>')
@login_required
def admin_delete_product(id):
    if not current_user.is_admin: return redirect(url_for('index'))
    p = Product.query.get_or_404(id)
    db.session.delete(p)
    db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/init-db')
def init_db():
    db.create_all()
    return "Database Check Complete"

if __name__ == '__main__':
    app.run(debug=True)
