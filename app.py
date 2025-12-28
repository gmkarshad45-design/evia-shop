import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'evia_official_secret'

# Database Configuration
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
    image = db.Column(db.String(500))    # Main Image
    image_2 = db.Column(db.String(500))  # Second Image (NEW)
    description = db.Column(db.Text)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_details = db.Column(db.Text)
    total_price = db.Column(db.Integer)
    status = db.Column(db.String(50), default="Placed")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date_ordered = db.Column(db.DateTime, default=datetime.utcnow)

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
            image_2=request.form.get('image_2'), # Added Second Image
            description=request.form.get('description')
        )
        db.session.add(new_p)
        db.session.commit()
        flash("Product Added Successfully!")
        return redirect(url_for('admin_panel'))
    
    products = Product.query.all()
    orders = Order.query.all()
    return render_template('admin.html', products=products, orders=orders)

@app.route('/admin/delete/<int:id>')
@login_required
def admin_delete_product(id):
    if not current_user.is_admin: return redirect(url_for('index'))
    p = Product.query.get_or_404(id)
    db.session.delete(p)
    db.session.commit()
    return redirect(url_for('admin_panel'))

# Add standard login/logout/cart routes here as per previous versions...

@app.route('/init-db')
def init_db():
    db.drop_all()
    db.create_all()
    admin = User(full_name="Admin", email="admin@test.com", 
                 password=generate_password_hash("admin123", method='pbkdf2:sha256'), is_admin=True)
    db.session.add(admin)
    db.session.commit()
    return "DB Updated. Admin: admin@test.com / admin123"

if __name__ == '__main__':
    app.run(debug=True)
