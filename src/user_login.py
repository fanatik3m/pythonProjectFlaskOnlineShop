from flask_login import UserMixin
from sqlalchemy import select

from src.models import User


class UserLogin(UserMixin):
    def from_db(self, user_id: int, db):
        query = select(User).where(User.id == user_id).limit(1)
        result = db.session.execute(query)
        self.__user = result.scalar_one().to_json()
        return self

    def create(self, user):
        self.__user = user
        return self

    def get_id(self):
        return str(self.__user.get('id'))

    def get_username(self):
        return str(self.__user.get('username'))

    def get_email(self):
        return str(self.__user.get('email'))