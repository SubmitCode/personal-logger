from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
# Import necessary modules
from forms import RegistrationForm
import json

app = Flask(__name__)
app.debug = True  # Enable debug mode
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.String, primary_key=True)
    password_hash = db.Column(db.String)

class HungerLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    hunger_level = db.Column(db.Integer, nullable=False)

@app.route('/get_hunger_data', methods=['GET'])
def get_hunger_data():
    logs = HungerLog.query.filter_by(user_id=current_user.id).all()
    hunger_data = [{"timestamp": log.timestamp.timestamp(), "hunger_level": log.hunger_level} for log in logs]
    return jsonify(hunger_data)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/edit_hunger/<int:log_id>', methods=['GET', 'POST'])
@login_required
def edit_hunger(log_id):
    log_entry = HungerLog.query.get_or_404(log_id)

    if log_entry.user_id != current_user.id:
        flash("You don't have permission to edit this entry.", 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        new_hunger_level = request.form.get('new_hunger_level')
        if new_hunger_level:
            log_entry.hunger_level = int(new_hunger_level)
            db.session.commit()
            flash('Hunger level updated successfully.', 'success')
            return redirect(url_for('home'))

    return render_template('edit_hunger.html', log_entry=log_entry)

@app.route('/delete_hunger/<int:log_id>', methods=['GET', 'POST'])
@login_required
def delete_hunger(log_id):
    log_entry = HungerLog.query.get_or_404(log_id)

    if log_entry.user_id != current_user.id:
        flash("You don't have permission to delete this entry.", 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        db.session.delete(log_entry)
        db.session.commit()
        flash('Hunger log entry deleted successfully.', 'success')
        return redirect(url_for('home'))

    return render_template('delete_hunger.html', log_entry=log_entry)

# Default route
@app.route('/')
def default():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    else:
        return redirect(url_for('home'))

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        hunger_level = request.form.get('hunger_level')
        if hunger_level:
            log_entry = HungerLog(user_id=current_user.id, hunger_level=hunger_level)
            db.session.add(log_entry)
            db.session.commit()
            flash(f'Logged hunger level {hunger_level}')
            return redirect(url_for('home'))

    # Retrieve log entries
    logs = HungerLog.query.filter_by(user_id=current_user.id).order_by(HungerLog.timestamp.desc()).all()
    
    return render_template('home.html', logs=logs)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(id=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials.')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/protected')
@login_required
def protected():
    return f'Logged in as: {current_user.id}'

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        # Check if the username is already taken
        existing_user = User.query.filter_by(id=form.username.data).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
        else:
            # Create a new user and store it in the database
            new_user = User(id=form.username.data, password_hash=generate_password_hash(form.password.data, method='scrypt'))
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('registration.html', form=form)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        hashed_password = generate_password_hash('mypassword', method='scrypt')
        new_user = User(id='myuser', password_hash=hashed_password)
        db.session.merge(new_user)
        db.session.commit()

    app.run(host='0.0.0.0', port=80)
