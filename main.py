import os
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, AnonymousUserMixin, login_user, LoginManager, login_required, \
    current_user, logout_user
from dotenv import load_dotenv, find_dotenv
import secrets

load_dotenv(find_dotenv(".env"))
DB_PATH = os.getenv('DB_PATH')
APPLICATION_ROOT = os.getenv('APPLICATION_ROOT')

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex()  # For now, just generate a new secret key each time.
app.config['UPLOAD_FOLDER'] = "static/files/"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['APPLICATION_ROOT'] = APPLICATION_ROOT
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin, db.Model, AnonymousUserMixin):  # DB TABLE
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

# with app.app_context():
#     db.create_all()


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(entity=User, ident=user_id)


@app.route('/')
def home():
    print(f"{current_user.is_anonymous = }")
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Todo - Find out: would it be time-consuming to iterate through the whole database (check if a user
        #  already exist) if there were thousands of users? How to know what is scalable? Is it better/faster
        #  to use try/except with flask-exceptions (e.g., 'IntegrityError')?

        if db.session.query(User).filter_by(email=request.form['email']).first():
            flash(message='An account with this email already exist. Try to log in instead 🫠', category='error')
            return redirect(url_for('login'))

        # Make new user. Replace plain text password with a salted hash:
        new_user = User()
        new_user.name = request.form['name']
        new_user.email = request.form['email']
        new_user.password = generate_password_hash(
            password=request.form['password'],
            method='pbkdf2:sha256',
            salt_length=8
        )
        # Log in new user.
        login_user(user=new_user, remember=False, force=False, fresh=True)
        return redirect(url_for('secrets'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = db.session.query(User).filter_by(email=request.form['email']).first()  # Get the user from database.
        entered_password = request.form['password']
        from flask import Markup
        # If user does not exist in database OR the entered password does not match the hash in the database:
        if not user or not check_password_hash(user.password, entered_password):
            message = Markup('Incorrect email or password. <br> Please try again')
            flash(message=message)
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('secrets'))

    return render_template("login.html")


# Todo: Read about how to check that a URL is safe. Should save the URL that the user came from in a
#  next-variable and return the user to that page after log in...

@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html")
    # # Todo: Read about LoginManager.unauthorized_handler().
    # # Instead of getting the 'unauthorized page' when trying to access '/secrets',
    # # redirect to '/login' and show the flash message there:
    # if not current_user.is_authenticated:
    #     flash(message="Unauthorized", category='error')
    #     flash(message="The server could not verify that you are authorized to access the "
    #                   "URL requested. You either supplied the wrong credentials (e.g. a "
    #                   "bad password), or your browser doesn't understand how to supply the "
    #                   "credentials required.", category='message')
    #     return redirect(url_for('login_get'))
    # else:
    #     return render_template("secrets.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')  # https://flask.palletsprojects.com/en/2.2.x/api/#flask.send_from_directory
@login_required
def download():
    return send_from_directory(directory=app.config['UPLOAD_FOLDER'],
                               path='cheat_sheet.pdf',
                               as_attachment=True,
                               download_name='flask_cheat_sheet.pdf')


@app.route('/test')
def test():
    flash("Test 1")
    flash("Testing...")
    flash("Ok, it's good.")
    return render_template("test.html")


if __name__ == "__main__":
    app.run(debug=True)
