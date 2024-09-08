from flask import Flask, render_template, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from flask_login import UserMixin
app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisisasecretkey'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# MongoDB connection
client = MongoClient('mongodb+srv://yogii006:Yogesh%40nt1@cluster0.liuwr.mongodb.net/')
db = client['inotebook']
collection = db['users']


class User(UserMixin):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def get_id(self):
        return self.username  # Or you can return any unique identifier for the user

    @staticmethod
    def find_by_username(username):
        user_data = collection.find_one({'username': username})
        if user_data:
            return User(user_data['username'], user_data['password'])
        return None
@login_manager.user_loader
def load_user(user_id):
    return User.find_by_username(user_id)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        if collection.find_one({'username': username.data}):
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.find_by_username(form.username.data)
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    status = 'login'
    username = current_user.username
    if username:
        status = 'logout'
        # MongoDB connection
        client = MongoClient('mongodb+srv://yogii006:Yogesh%40nt1@cluster0.liuwr.mongodb.net/')
        db = client['inotebook']
        collection = db['notes']
        note_data = collection.find({"username":username})
        if note_data:
            note = []
            for i in note_data:
                note.append(i["note"])
        else:
            note = 'empty'
    else:
        status = login
    
    return render_template('dashboard.html',l=note,username=username,status = status)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
@app.route('/fetchnotes')
@login_required
def fetchnotes():
    username = current_user.username
    client = MongoClient('mongodb+srv://yogii006:Yogesh%40nt1@cluster0.liuwr.mongodb.net/')
    db = client['inotebook']
    collection = db['notes']
    notes = collection.find({"username":username})
    return render_template('dashboard.html',l=notes)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user_data = {'username': form.username.data, 'password': hashed_password}
        # MongoDB connection
        client = MongoClient('mongodb+srv://yogii006:Yogesh%40nt1@cluster0.liuwr.mongodb.net/')
        db = client['inotebook']
        collection = db['users']
        collection.insert_one(user_data)
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
