from typing import Callable

from flask import redirect, url_for
from flask_login import current_user


def redirect_authorized_users(func: Callable):
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect(url_for('.profile'))
        return func(*args, **kwargs)
    return wrapper