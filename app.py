from crypt import methods
import bcrypt
from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model , UserMixin):
    id = db.Column(db.Integer , primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(30), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4 , max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4 , max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("Username already exists. Type different one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4 , max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4 , max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

class ProfileForm(FlaskForm):
    petname = StringField(validators=[InputRequired(), Length(min=4 , max=40)], render_kw={"placeholder": "Pet's name"})
    kind = StringField(validators=[InputRequired(), Length(min=1 , max=40)], render_kw={"placeholder": "Ex: dog, cat, bird,..."})
    gender = StringField(validators=[InputRequired(), Length(min=4 , max=20)], render_kw={"placeholder": "Gender"})
    submit = SubmitField("Save")

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    FORM = LoginForm()
    if FORM.validate_on_submit():
        user = User.query.filter_by(username = FORM.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, FORM.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form = FORM)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    return render_template('profile.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    FORM = RegisterForm()

    if FORM.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(FORM.password.data)
        new_user = User(username = FORM.username.data, password = hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html', form=FORM)

if __name__ == "__name__":
    app.run(debug=True)

# FLASH_APP=app.py flask run