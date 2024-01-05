from wtforms import Form, StringField, PasswordField, IntegerField, validators
from wtforms.validators import DataRequired

class SignUpForm(Form):
    first_name = StringField('First Name', [validators.Length(min=1, max=100)])
    last_name = StringField('Last Name', [validators.Length(min=1, max=100)])
    email = StringField(
        'Email address', [validators.DataRequired(), validators.Email()])
    username = StringField('Username', [validators.Length(min=4, max=100)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

class LoginForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=100)])
    password = PasswordField('Password', [
        validators.DataRequired(),
    ])

class TransactionForm(Form):
    amount = IntegerField('Amount', validators=[DataRequired()])
    description = StringField('Description', [validators.Length(min=1)])

class RequestResetForm(Form):
    email = StringField(
        'Email address', [validators.DataRequired(), validators.Email()])
    
class ResetPasswordForm(Form):
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')