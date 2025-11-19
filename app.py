from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = "abc123"

# Kết nối MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:123456@localhost/userdb'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


# MODEL USERS
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    email = db.Column(db.String(100))
    password = db.Column(db.String(255))
    role = db.Column(db.String(20))


@app.route('/')
def index():
    return redirect('/login')


# ĐĂNG KÝ
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password'])

        new_user = User(username=username, email=email, password=password, role="user")
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')

    return render_template('register.html')


# ĐĂNG NHẬP
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user'] = username
            session['role'] = user.role
            return redirect('/dashboard')

    return render_template('login.html')


# DASHBOARD
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')

    return render_template('dashboard.html', user=session['user'], role=session['role'])


# ADMIN ONLY
@app.route('/admin')
def admin():
    if session.get('role') != "admin":
        return "Bạn không có quyền truy cập!"

    users = User.query.all()
    return {
        "users": [{ "username": u.username, "role": u.role } for u in users]
    }


if __name__ == '__main__':
    app.run(debug=True)