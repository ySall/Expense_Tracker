from flask import Flask
from flask_mail import Mail
from flask_mysqldb import MySQL

app = Flask(__name__, static_url_path='/static')
app.config.from_pyfile('config.py')
app.config['TEMPLATES_AUTO_RELOAD'] = True

mysql = MySQL()
mail = Mail()

from app import routes

mysql.init_app(app)  # Move this line here
mail.init_app(app)   # Move this line here
