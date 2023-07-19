from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask import session, abort

from src.extensions import db
from src.models import User, Product, Order

admin = Admin()


class SecurityModelView(ModelView):
    def is_accessible(self):
        if session.get('admin_logged_in'):
            return True
        else:
            abort(401)


admin.add_view(SecurityModelView(User, db.session))
admin.add_view(SecurityModelView(Product, db.session))
admin.add_view(SecurityModelView(Order, db.session))