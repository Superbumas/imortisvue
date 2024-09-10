from flask import Flask, render_template, redirect, url_for, flash, jsonify, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField, DateField, FileField, FieldList, FormField
from wtforms.validators import DataRequired, Length, ValidationError, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import qrcode
import os
import base64
import logging
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ThisIsASecretKey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    bio = db.Column(db.Text, nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    date_of_death = db.Column(db.Date, nullable=False)
    profile_picture = db.Column(db.String(100), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('profiles', lazy=True))
    timelines = db.relationship('Timeline', backref='profile', lazy=True)

class Timeline(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    event = db.Column(db.String(255), nullable=False)
    profile_id = db.Column(db.Integer, db.ForeignKey('profile.id'), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=100)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class TimelineForm(FlaskForm):
    date = DateField('Date', format='%Y-%m-%d', validators=[DataRequired()])
    event = StringField('Event', validators=[DataRequired(), Length(max=255)])

class ProfileForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=100)])
    bio = TextAreaField('Bio', validators=[DataRequired()])
    date_of_birth = DateField('Date of Birth', format='%Y-%m-%d', validators=[DataRequired()])
    date_of_death = DateField('Date of Death', format='%Y-%m-%d', validators=[DataRequired()])
    profile_picture = FileField('Profile Picture')
    timelines = FieldList(FormField(TimelineForm), min_entries=1, max_entries=10)
    submit = SubmitField('Create Profile')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))  # Redirect to dashboard after login
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

def generate_qr(data, filename):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    
    # Ensure the directory exists
    qr_code_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'qr_codes')
    os.makedirs(qr_code_dir, exist_ok=True)
    
    # Save the image
    file_path = os.path.join(qr_code_dir, filename)
    img.save(file_path)
    
    return file_path


@app.route('/api/profiles')
@login_required
def api_profiles():
    try:
        profiles = Profile.query.filter_by(user_id=current_user.id).all()
        profiles_data = [
            {
                "id": profile.id,
                "name": profile.name,
                "bio": profile.bio,
                "date_of_birth": profile.date_of_birth.strftime('%Y-%m-%d'),
                "date_of_death": profile.date_of_death.strftime('%Y-%m-%d'),
                "timelines": [
                    {
                        "date": timeline.date.strftime('%Y-%m-%d'),
                        "event": timeline.event
                    } for timeline in profile.timelines
                ]
            } for profile in profiles
        ]
        return jsonify(profiles_data)
    except Exception as e:
        app.logger.error(f"Error fetching profiles: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/create_profile', methods=['GET', 'POST'])
@login_required
def create_profile():
    form = ProfileForm()
    if form.validate_on_submit():
        try:

            session.pop('_flashes', None)

            profile_picture = None
            if form.profile_picture.data:
                filename = secure_filename(form.profile_picture.data.filename)
                upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                os.makedirs(os.path.dirname(upload_path), exist_ok=True)
                form.profile_picture.data.save(upload_path)
                profile_picture = filename

            new_profile = Profile(
                name=form.name.data,
                bio=form.bio.data,
                date_of_birth=form.date_of_birth.data,
                date_of_death=form.date_of_death.data,
                profile_picture=profile_picture,
                user_id=current_user.id
            )
            db.session.add(new_profile)
            db.session.flush()  # This assigns an ID to new_profile

            for timeline_form in form.timelines:
                new_timeline = Timeline(
                    date=timeline_form.date.data,
                    event=timeline_form.event.data,
                    profile_id=new_profile.id
                )
                db.session.add(new_timeline)
            
            db.session.commit()
            flash('Profile created successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
    
    # If form validation fails, this will show errors
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"Error in {getattr(form, field).label.text}: {error}", 'danger')
    
    return render_template('create_profile.html', form=form)

@app.route('/profile/<string:profile_name>')
def view_profile(profile_name):
    profile = Profile.query.filter_by(name=profile_name).first_or_404()
    return render_template('view_profile.html', profile=profile)


@app.route('/edit_profile/<profile_name>', methods=['GET', 'POST'])
@login_required
def edit_profile(profile_name):
    profile = Profile.query.filter_by(name=profile_name).first_or_404()
    if profile.user_id != current_user.id:
        flash('You do not have permission to edit this profile.', 'danger')
        return redirect(url_for('dashboard'))
    
    form = ProfileForm(obj=profile)
    
    # Populate timelines in the form
    if request.method == 'GET':
        for timeline in profile.timelines:
            form.timelines.append_entry({
                'date': timeline.date,
                'event': timeline.event
            })
    
    if form.validate_on_submit():
        try:
            profile.name = form.name.data
            profile.bio = form.bio.data
            profile.date_of_birth = form.date_of_birth.data
            profile.date_of_death = form.date_of_death.data
            
            if form.profile_picture.data:
                filename = secure_filename(form.profile_picture.data.filename)
                upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                os.makedirs(os.path.dirname(upload_path), exist_ok=True)
                form.profile_picture.data.save(upload_path)
                profile.profile_picture = filename
            
            db.session.commit()

            # Update timelines
            Timeline.query.filter_by(profile_id=profile.id).delete()
            for timeline_form in form.timelines:
                new_timeline = Timeline(
                    date=timeline_form.date.data,
                    event=timeline_form.event.data,
                    profile_id=profile.id
                )
                db.session.add(new_timeline)
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
    
    return render_template('edit_profile.html', form=form, profile=profile)

@app.route('/delete_profile/<int:profile_id>', methods=['POST'])
@login_required
def delete_profile(profile_id):
    profile = Profile.query.get_or_404(profile_id)
    if profile.user_id != current_user.id:
        flash('You do not have permission to delete this profile.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Delete associated timelines
        Timeline.query.filter_by(profile_id=profile.id).delete()
        
        # Delete the profile
        db.session.delete(profile)
        db.session.commit()
        flash('Profile deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while deleting the profile: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)