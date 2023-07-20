from flask import Blueprint, request, url_for, redirect, render_template, session, abort, flash
from flask_login import LoginManager, login_user, current_user, login_required
from sqlalchemy import insert, select, delete, update

from werkzeug.security import generate_password_hash, check_password_hash

from src.extensions import db
from src.forms import LoginUserForm, RegisterUserForm, CreateProductForm
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
    return render_template('index.html', title='Main page')


@main_app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterUserForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        stmt = insert(User).values(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.execute(stmt)
        db.session.commit()

    return render_template('register.html', title='Register', form=form)


@main_app.route('/login', methods=['POST', 'GET'])
@redirect_authorized_users
def login():
    form = LoginUserForm()
    if form.validate_on_submit():
        try:
            query = select(User).where(User.email == form.email.data).limit(1)
            user = db.session.execute(query).scalar_one().to_json()
            if user and check_password_hash(user.get('password'), form.password.data):
                user_login = UserLogin().create(user)
                login_user(user_login, remember=form.remember.data)
                return redirect(url_for('.profile'))
        except Exception as ex:
            flash(str(ex))
        flash('Got non-valid data')

    return render_template('login_user.html', title='Log in', form=form)


@main_app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', title='Profile', id=current_user.get_id(),
                           username=current_user.get_username(), email=current_user.get_email())


@main_app.route('/products', methods=['POST', 'GET'])
@login_required
def create_product():
    form = CreateProductForm()
    if form.validate_on_submit():
        try:
            stmt = insert(Product).values(title=form.title.data, description=form.description.data,
                                          category=form.category.data, creator_id=current_user.get_id())
            db.session.execute(stmt)
            db.session.commit()
            flash('Product created')
        except Exception as ex:
            print(str(ex))
            return redirect(url_for('.index'))

    return render_template('create_product.html', title='Create product', form=form)


@main_app.route('/products/self/<int:page>')
@login_required
def check_self_products(page):
    try:
        offset = (page - 1) * 10

        query = select(Product).where(Product.creator_id == current_user.get_id()).offset(offset).limit(10)
        result = db.session.execute(query)

        return render_template('check_self_products.html', title='Check products',
                               data=[row[0].to_json() for row in result.all()])
    except Exception as ex:
        print(str(ex))
        return redirect(url_for('.index'))


@main_app.route('/products/self/<product_title>')
@login_required
def check_self_product_by_title(product_title):
    try:
        query = select(Product).where(Product.creator_id == current_user.get_id()).where(
            Product.title == product_title).limit(1)
        result = db.session.execute(query)
        return render_template('check_titled_products.html', data=result.scalar_one().to_json())
    except Exception as ex:
        print(str(ex))
        return redirect(url_for('.index'))


@main_app.route('/products/category/<category_name>')
@login_required
def check_products_by_category(category_name):
    try:
        query = select(Product).where(Product.category == category_name)
        result = db.session.execute(query)

        return render_template('check_categoried_products.html', data=[row[0].to_json() for row in result.all()])
    except Exception as ex:
        print(str(ex))
        return redirect(url_for('.index'))


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


@main_app.route('/orders/<int:product_id>', methods=['GET'])
@login_required
def create_order(product_id):
    try:
        query = select(Product).where(Product.id == product_id).limit(1)
        product = db.session.execute(query).scalar_one().to_json()

        stmt = insert(Order).values(product_id=product_id, customer_id=current_user.get_id(),
                                    seller_id=product.get('creator_id'))
        db.session.execute(stmt)
        db.session.commit()
        return render_template('order_created.html', title='Order created')
    except Exception as ex:
        print(str(ex))
        return redirect(url_for('.index'))


@main_app.route('/orders/self/<int:page>')
@login_required
def check_self_orders(page):
    try:
        offset = (page - 1) * 10

        query = select(Order).where(Order.customer_id == current_user.get_id()).offset(offset).limit(10)
        result = db.session.execute(query)
        return render_template('check_self_orders.html', data=[row[0].to_json() for row in result.all()])
    except Exception as ex:
        print(str(ex))
        return redirect(url_for('.index'))


@main_app.route('/orders/self_own/<int:page>')
@login_required
def check_orders_of_your_products(page):
    try:
        offset = (page - 1) * 10

        query = select(Order).where(Order.seller_id == current_user.get_id()).offset(offset).limit(10)
        result = db.session.execute(query)
        return render_template('check_self_own_orders.html', data=[row[0].to_json() for row in result.all()])
    except Exception as ex:
        print(str(ex))
        return redirect(url_for('.index'))


@main_app.route('/orders/<int:order_id>', methods=['PUT'])
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


@main_app.route('/admin_log', methods=['GET', 'POST'])
def admin_log():
    if request.method == 'POST':
        if request.form.get('username') == 'admin_admin_app' and request.form.get(
                'password') == 'usa9dyasd7827838r238reiijklsfnjjdskhfskdjfhsdkjfhsdklaqwpo':
            session['admin_logged_in'] = True
            return redirect('/admin')
        else:
            abort(401)

    return render_template('login.html')
