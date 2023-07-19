from datetime import datetime

from src.extensions import db


class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), unique=True, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    registered_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)

    def to_json(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'password': self.password,
            'registered_at': self.registered_at
        }


class Product(db.Model):
    __tablename__ = 'product'
    __table_args__ = (
        db.UniqueConstraint('title', 'creator_id', name='unique_title_creator_id'),
    )

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    description = db.Column(db.String, nullable=False)
    category = db.Column(db.String, nullable=False)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    creator_id = db.Column(db.Integer, db.ForeignKey(User.id))

    def to_json(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'category': self.category,
            'created_at': self.created_at,
            'creator_id': self.creator_id
        }


class Order(db.Model):
    __tablename__ = 'order'

    id = db.Column(db.Integer, primary_key=True)
    is_completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    product_id = db.Column(db.Integer, db.ForeignKey(Product.id))
    seller_id = db.Column(db.Integer, db.ForeignKey(User.id))
    customer_id = db.Column(db.Integer, db.ForeignKey(User.id))

    def to_json(self):
        return {
            'id': self.id,
            'is_completed': self.is_completed,
            'created_at': self.created_at,
            'product_id': self.product_id,
            'seller_id': self.seller_id,
            'customer_id': self.customer_id
        }