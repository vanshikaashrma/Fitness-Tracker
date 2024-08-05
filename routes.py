from flask import render_template, url_for, flash, redirect
from app import app, db, bcrypt
from forms import RegistrationForm, LoginForm, WorkoutForm
from models import User, Workout
from flask_login import login_user, current_user, logout_user, login_required

@app.route('/')
@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    workouts = Workout.query.filter_by(author=current_user)
    return render_template('dashboard.html', workouts=workouts)

@app.route('/workout/new', methods=['GET', 'POST'])
@login_required
def new_workout():
    form = WorkoutForm()
    if form.validate_on_submit():
        workout = Workout(exercise=form.exercise.data, sets=form.sets.data, reps=form.reps.data, weight=form.weight.data, author=current_user)
        db.session.add(workout)
        db.session.commit()
        flash('Your workout has been added!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_workout.html', title='New Workout', form=form, legend='New Workout')
