from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, PasswordField
from wtforms.validators import Email, Length, DataRequired


class LoginUserForm(FlaskForm):
    email = StringField('Email: ', validators=[Email()])
    password = PasswordField('Password: ', validators=[DataRequired(), Length(min=4, max=100)])
    remember = BooleanField('Remember me: ', default=False)
    submit = SubmitField('Enter')


class RegisterUserForm(FlaskForm):
    username = StringField('Username: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[Email()])
    password = PasswordField('Password: ', validators=[DataRequired(), Length(min=4, max=100)])
    submit = SubmitField('Enter')


class CreateProductForm(FlaskForm):
    title = StringField('Title: ', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    category = StringField('Category: ', validators=[DataRequired()])
    submit = SubmitField('Create')
