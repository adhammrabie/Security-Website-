from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.secret_key = "your_secret_key"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

with app.app_context():
    db.create_all()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), nullable=False)


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.secret_key = "your_secret_key"  
db.init_app(app)


hashed_password_ceo = bcrypt.generate_password_hash('CEO').decode('utf-8')
hashed_password_employee = bcrypt.generate_password_hash('EMPLOYEE').decode('utf-8')

users = {
    'GREAZECEO': {'password': hashed_password_ceo, 'role': 'CEO'},
    'GREAZEEMPLOYEE': {'password': hashed_password_employee, 'role': 'Employee'}
}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user is one of the hardcoded users
        if username in users and bcrypt.check_password_hash(users[username]['password'], password):
            session['logged_in'] = True
            session['username'] = username
            role = users[username]['role']

            # Redirect based on user role
            if role == 'CEO':
                return redirect(url_for('ceo_office'))
            elif role == 'Employee':
                return redirect(url_for('dashboard'))

        # If not a hardcoded user, query the database for user credentials
        user = User.query.filter_by(username=username).first()

        # Check if the user exists and the password is correct
        if user and bcrypt.check_password_hash(user.password, password):
            session['logged_in'] = True
            session['username'] = user.username
            role = user.role

            # Redirect based on user role
            if role == 'CEO':
                return redirect(url_for('ceo_office'))
            elif role == 'Employee':
                return redirect(url_for('dashboard'))

        # Invalid credentials
        flash('Invalid credentials', 'error')
        return render_template('login.html', error='Invalid credentials')

    return render_template('login.html', error=None)

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    username = session['username']
    return render_template('dashboard.html', username=username)

@app.route('/ceo_office')
def ceo_office():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    username = session['username']
    role = users.get(username, {}).get('role', 'Employee')
    
    if role == 'CEO':
        return render_template('ceo_office.html', username=username)
    else:
        flash("This page can only be accessed by the CEO of Greaze", 'error')
        return redirect(url_for('dashboard'))

@app.route('/about_page')  
def about_page():
    return render_template('about_page.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        new_username = request.form['new_username']
        new_password = request.form['new_password']

        # Validate password length
        if 8 <= len(new_password) <= 15:
            # Check if the username is already taken
            if not User.query.filter_by(username=new_username).first():
                # Save user data to the database with hashed password
                hashed_password = bcrypt.generate_password_hash(new_password)
                new_user = User(username=new_username, password=hashed_password, role='Employee')
                db.session.add(new_user)
                db.session.commit()

                flash("Signup successful! Please login with your new credentials.", 'success')
                return redirect(url_for('login'))
            else:
                flash("Username is already taken. Please choose a different one.", 'error')
        else:
            flash("Password must be between 8 and 15 characters.", 'error')

    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)