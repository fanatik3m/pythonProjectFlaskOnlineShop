from flask import Blueprint, request, url_for, redirect, render_template, session, abort
from flask_login import LoginManager, login_user, current_user, login_required
from sqlalchemy import insert, select, delete, update

from werkzeug.security import generate_password_hash, check_password_hash

from src.extensions import db
from src.models import User, Product, Order
from src.user_login import UserLogin
from src.utils import redirect_authorized_users

main_app = Blueprint('main_app', __name__, template_folder='templates', static_folder='static')

login_manager = LoginManager()


@login_manager.user_loader
def load_user(user_id):
    return UserLogin().from_db(user_id, db)


@main_app.route('/')
@main_app.route('/index')
def index():
    return 'hi from main_app blueprint'


@main_app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    try:
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        hashed_password = generate_password_hash(password)

        stmt = insert(User).values(username=username, email=email, password=hashed_password)
        db.session.execute(stmt)
        db.session.commit()
        return {'status': 'ok', 'details': {}, 'data': {}}
    except Exception as ex:
        print(ex)
        return {'status': 'error', 'details': {'msg': 'got non-valid data'}, 'data': {}}


@main_app.route('/login', methods=['POST'])
@redirect_authorized_users
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    remember: bool = True if data.get('remember') else False

    query = select(User).where(User.email == email).limit(1)
    user = db.session.execute(query).scalar_one().to_json()
    if user and check_password_hash(user.get('password'), password):
        user_login = UserLogin().create(user)
        login_user(user_login, remember=remember)
        return redirect(url_for('.profile'))
    else:
        return {'status': 'error', 'details': {'msg': 'got non-valid data'}, 'data': {}}


@main_app.route('/profile')
@login_required
def profile():
    return {
        'id': current_user.get_id(),
        'username': current_user.get_username(),
        'email': current_user.get_email()
    }


@main_app.route('/products', methods=['POST'])
@login_required
def create_product():
    try:
        data = request.get_json()
        stmt = insert(Product).values(title=data.get('title'), description=data.get('description'),
                                      category=data.get('category'), creator_id=current_user.get_id())
        db.session.execute(stmt)
        db.session.commit()
        return {
            'status': 'ok',
            'details': {},
            'data': {}
        }
    except Exception as ex:
        print(ex)
        return {
            'status': 'error',
            'details': {},
            'data': {}
        }


@main_app.route('/products/self/<int:page>')
@login_required
def check_self_products(page):
    try:
        offset = (page - 1) * 10

        query = select(Product).where(Product.creator_id == current_user.get_id()).offset(offset).limit(10)
        result = db.session.execute(query)
        return {
            'status': 'ok',
            'details': {},
            'data': [row[0].to_json() for row in result.all()]
        }
    except Exception as ex:
        print(ex)
        return {
            'status': 'error',
            'details': {},
            'data': {}
        }


@main_app.route('/products/self/<product_title>')
@login_required
def check_self_product_by_title(product_title):
    try:
        query = select(Product).where(Product.creator_id == current_user.get_id()).where(
            Product.title == product_title).limit(1)
        result = db.session.execute(query)
        return {
            'status': 'ok',
            'details': {},
            'data': result.scalar_one().to_json()
        }
    except Exception as ex:
        print(ex)
        return {
            'status': 'error',
            'details': {},
            'data': {}
        }


@main_app.route('/products/category/<category_name>')
@login_required
def check_products_by_category(category_name):
    try:
        query = select(Product).where(Product.category == category_name)
        result = db.session.execute(query)
        return {
            'status': 'ok',
            'details': {},
            'data': [row[0].to_json() for row in result.all()]
        }
    except Exception as ex:
        print(ex)
        return {
            'status': 'error',
            'details': {},
            'data': {}
        }


@main_app.route('/products/self/<product_title>', methods=['DELETE'])
@login_required
def delete_product(product_title):
    try:
        stmt = delete(Product).where(Product.title == product_title).where(Product.creator_id == current_user.get_id())
        db.session.execute(stmt)
        db.session.commit()
        return {
            'status': 'ok',
            'details': {},
            'data': {}
        }
    except Exception as ex:
        print(ex)
        return {
            'status': 'error',
            'details': {},
            'data': {}
        }


@main_app.route('/orders', methods=['POST'])
@login_required
def create_order():
    try:
        data = request.get_json()

        query = select(Product).where(Product.id == data.get('product_id')).limit(1)
        product = db.session.execute(query).scalar_one().to_json()

        stmt = insert(Order).values(product_id=data.get('product_id'), customer_id=current_user.get_id(),
                                    seller_id=product.creator_id)
        db.session.execute(stmt)
        db.session.commit()
        return {
            'status': 'ok',
            'details': {},
            'data': {}
        }
    except Exception as ex:
        print(ex)
        return {
            'status': 'error',
            'details': {},
            'data': {}
        }


@main_app.route('/orders/self/<int:page>')
@login_required
def check_self_orders(page):
    try:
        offset = (page - 1) * 10

        query = select(Order).where(Order.customer_id == current_user.get_id()).offset(offset).limit(10)
        result = db.session.execute(query)
        return {
            'status': 'ok',
            'details': {},
            'data': [row[0].to_json() for row in result.all()]
        }
    except Exception as ex:
        print(ex)
        return {
            'status': 'error',
            'details': {},
            'data': {}
        }


@main_app.route('/orders/<int:page>')
@login_required
def check_orders_of_your_products(page):
    try:
        offset = (page - 1) * 10

        query = select(Order).where(Order.seller_id == current_user.get_id()).offset(offset).limit(10)
        result = db.session.execute(query)
        return {
            'status': 'ok',
            'details': {},
            'data': [row[0].to_json() for row in result.all()]
        }
    except Exception as ex:
        print(ex)
        return {
            'status': 'error',
            'details': {},
            'data': {}
        }


@main_app.route('/orders/<int:order_id>', method=['PUT'])
@login_required
def update_order_status(order_id):
    try:
        stmt = update(Order).where(Order.id == order_id).where(Order.seller_id == current_user.get_id()).values(
            is_completed=True)
        db.session.execute(stmt)
        db.session.commit()
        return {
            'status': 'ok',
            'details': {},
            'data': {}
        }
    except Exception as ex:
        print(ex)
        return {
            'status': 'error',
            'details': {},
            'data': {}
        }


@main_app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if request.form.get('username') == 'admin_admin_app' and request.form.get(
                'password') == 'usa9dyasd7827838r238reiijklsfnjjdskhfskdjfhsdkjfhsdklaqwpo':
            session['admin_logged_in'] = True
            return redirect('/admin')
        else:
            abort(401)

    return render_template('login.html')
