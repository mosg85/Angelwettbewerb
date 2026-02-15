#!/bin/bash
# Полная установка Angelwettbewerb с таблицей результатов

cd ~/angelwettbewerb

echo "🐍 Создание виртуального окружения"
python -m venv venv
source venv/bin/activate

echo "📥 Установка Python-пакетов"
pip install --upgrade pip
pip install flask flask-sqlalchemy flask-wtf flask-login flask-migrate email-validator \
            werkzeug pillow python-dotenv alembic flask-mail

echo "📁 Создание структуры папок"
mkdir -p static/css static/js static/img static/uploads logs templates/errors \
         templates/auth templates/user templates/admin templates/competition \
         routes forms utils

# ======================== ФАЙЛЫ ПРИЛОЖЕНИЯ ========================

cat > app.py << 'EOF'
import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_mail import Mail
from config import Config

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Bitte melde dich an, um diese Seite zu sehen.'
login_manager.login_message_category = 'info'
mail = Mail()
migrate = Migrate()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)

    @login_manager.user_loader
    def load_user(user_id):
        from models import User
        return User.query.get(int(user_id))

    if not app.debug:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Angelwettbewerb Start')

    from routes.main import main_bp
    from routes.auth import auth_bp
    from routes.user import user_bp
    from routes.admin import admin_bp
    from routes.competition import comp_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(comp_bp)

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('errors/500.html'), 500

    return app

app = create_app()
EOF

cat > config.py << 'EOF'
import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'schwer-zu-erraten-123'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(basedir, 'static/uploads')
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.googlemail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@angelwettbewerb.local')
EOF

cat > models.py << 'EOF'
from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    vorname = db.Column(db.String(64), nullable=False)
    nachname = db.Column(db.String(64), nullable=False)
    telefon = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    photo_path = db.Column(db.String(256), default='default_avatar.png')
    is_admin = db.Column(db.Boolean, default=False)
    email_confirmed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def full_name(self):
        return f"{self.vorname} {self.nachname}"

class Competition(db.Model):
    __tablename__ = 'competitions'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    zeit = db.Column(db.DateTime, nullable=False)
    ort = db.Column(db.String(128), nullable=False)
    plaetze = db.Column(db.Integer, default=10)
    max_teilnehmer = db.Column(db.Integer, default=20)
    beschreibung = db.Column(db.Text)
    regeln = db.Column(db.Text)
    status = db.Column(db.String(20), default='created')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    participants = db.relationship('Participant', backref='competition', lazy='dynamic', cascade='all, delete-orphan')
    rounds = db.relationship('Round', backref='competition', lazy='dynamic', cascade='all, delete-orphan')

class Participant(db.Model):
    __tablename__ = 'participants'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comp_id = db.Column(db.Integer, db.ForeignKey('competitions.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='participations')

class Round(db.Model):
    __tablename__ = 'rounds'
    id = db.Column(db.Integer, primary_key=True)
    comp_id = db.Column(db.Integer, db.ForeignKey('competitions.id'), nullable=False)
    round_num = db.Column(db.Integer, nullable=False)
    started = db.Column(db.Boolean, default=False)
    finished = db.Column(db.Boolean, default=False)
    places = db.relationship('Place', backref='round', lazy='dynamic', cascade='all, delete-orphan')

class Place(db.Model):
    __tablename__ = 'places'
    id = db.Column(db.Integer, primary_key=True)
    round_id = db.Column(db.Integer, db.ForeignKey('rounds.id'), nullable=False)
    place_num = db.Column(db.Integer, nullable=False)
    left_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    right_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    left_user = db.relationship('User', foreign_keys=[left_user_id])
    right_user = db.relationship('User', foreign_keys=[right_user_id])
    results = db.relationship('Result', backref='place', lazy='dynamic', cascade='all, delete-orphan')

class Result(db.Model):
    __tablename__ = 'results'
    id = db.Column(db.Integer, primary_key=True)
    place_id = db.Column(db.Integer, db.ForeignKey('places.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    fish_count = db.Column(db.Integer, default=0)
    confirmed = db.Column(db.Boolean, default=False)
    photo_path = db.Column(db.String(256))
    dispute = db.Column(db.Boolean, default=False)
    points_awarded = db.Column(db.Integer, default=0)
    user = db.relationship('User')
EOF

# ======================== ФОРМЫ ========================

cat > forms/auth.py << 'EOF'
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp
from models import User

class RegistrationForm(FlaskForm):
    vorname = StringField('Vorname', validators=[DataRequired(), Length(min=2, max=64)])
    nachname = StringField('Nachname', validators=[DataRequired(), Length(min=2, max=64)])
    telefon = StringField('Telefon', validators=[DataRequired(), 
                          Regexp(r'^\+49[0-9]{7,15}$', message='Bitte eine gültige deutsche Telefonnummer mit +49 eingeben.')])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Passwort', validators=[DataRequired(), Length(min=8, message='Mindestens 8 Zeichen')])
    password2 = PasswordField('Passwort wiederholen', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrieren')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Diese Email wird bereits verwendet.')

    def validate_telefon(self, telefon):
        if User.query.filter_by(telefon=telefon.data).first():
            raise ValidationError('Diese Telefonnummer ist bereits registriert.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Passwort', validators=[DataRequired()])
    admin_mode = BooleanField('Als Administrator anmelden')
    submit = SubmitField('Einloggen')
EOF

cat > forms/competition.py << 'EOF'
from flask_wtf import FlaskForm
from wtforms import StringField, DateTimeField, IntegerField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, NumberRange, ValidationError

class CompetitionForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    zeit = DateTimeField('Zeit (JJJJ-MM-TT HH:MM)', format='%Y-%m-%d %H:%M', validators=[DataRequired()])
    ort = StringField('Ort', validators=[DataRequired()])
    plaetze = IntegerField('Anzahl Plätze', validators=[DataRequired(), NumberRange(min=2, max=50)], default=10)
    max_teilnehmer = IntegerField('Maximale Teilnehmer', validators=[DataRequired(), NumberRange(min=2)], default=20)
    beschreibung = TextAreaField('Beschreibung')
    regeln = TextAreaField('Regeln')
    submit = SubmitField('Wettbewerb erstellen')

    def validate_max_teilnehmer(form, field):
        if field.data % 2 != 0:
            raise ValidationError('Die maximale Teilnehmerzahl muss gerade sein.')
        if field.data != 2 * form.plaetze.data:
            raise ValidationError('Maximale Teilnehmer müssen = 2 * Plätze sein.')

class ResultForm(FlaskForm):
    fish_count = IntegerField('Anzahl Fische', validators=[DataRequired(), NumberRange(min=0)], default=0)
    submit = SubmitField('Bestätigen')
EOF

# ======================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ========================

cat > utils/decorators.py << 'EOF'
from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Diese Seite ist nur für Administratoren.', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function
EOF

cat > utils/helpers.py << 'EOF'
import os
from werkzeug.utils import secure_filename
from flask import current_app
from PIL import Image
import random

def save_photo(form_photo, folder='avatars'):
    if not form_photo:
        return 'default_avatar.png'
    filename = secure_filename(form_photo.filename)
    name, ext = os.path.splitext(filename)
    filename = name + '_' + str(random.randint(1000,9999)) + ext
    try:
        upload_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], folder)
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        filepath = os.path.join(upload_folder, filename)
        form_photo.save(filepath)
        img = Image.open(filepath)
        img.thumbnail((300, 300))
        img.save(filepath)
        return os.path.join(folder, filename)
    except Exception as e:
        print(f"Fehler beim Speichern: {e}")
        return 'default_avatar.png'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}
EOF

# ======================== МАРШРУТЫ ========================

cat > routes/main.py << 'EOF'
from flask import Blueprint, render_template

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/impressum')
def impressum():
    return render_template('impressum.html')
EOF

cat > routes/auth.py << 'EOF'
from flask import Blueprint, render_template, flash, redirect, url_for, request
from flask_login import login_user, logout_user, login_required, current_user
from models import User, db
from forms.auth import RegistrationForm, LoginForm

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            vorname=form.vorname.data,
            nachname=form.nachname.data,
            telefon=form.telefon.data,
            email=form.email.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registrierung erfolgreich! Du kannst dich jetzt einloggen.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            if form.admin_mode.data and not user.is_admin:
                flash('Du bist kein Administrator.', 'danger')
                return render_template('auth/login.html', form=form)
            login_user(user, remember=True)
            next_page = request.args.get('next')
            flash('Erfolgreich eingeloggt.', 'success')
            if user.is_admin:
                return redirect(next_page) if next_page else redirect(url_for('admin.dashboard'))
            else:
                return redirect(next_page) if next_page else redirect(url_for('user.dashboard'))
        else:
            flash('Ungültige Email oder Passwort.', 'danger')
    return render_template('auth/login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Du wurdest abgemeldet.', 'info')
    return redirect(url_for('main.index'))
EOF

cat > routes/user.py << 'EOF'
from flask import Blueprint, render_template, flash, redirect, url_for, request
from flask_login import login_required, current_user
from models import Competition, Participant, db, Round, Place, Result
from forms.competition import ResultForm
from utils.helpers import save_photo

user_bp = Blueprint('user', __name__)

@user_bp.route('/dashboard')
@login_required
def dashboard():
    competitions = Competition.query.filter(Competition.status.in_(['created', 'started', 'ongoing'])).all()
    participated_ids = [p.comp_id for p in current_user.participations]
    return render_template('user/dashboard.html', competitions=competitions, participated_ids=participated_ids)

@user_bp.route('/competition/<int:comp_id>/join')
@login_required
def join_competition(comp_id):
    comp = Competition.query.get_or_404(comp_id)
    if comp.status != 'created':
        flash('Dieser Wettbewerb hat bereits begonnen.', 'warning')
        return redirect(url_for('user.dashboard'))
    if comp.participants.count() >= comp.max_teilnehmer:
        flash('Der Wettbewerb ist bereits voll.', 'danger')
        return redirect(url_for('user.dashboard'))
    if Participant.query.filter_by(user_id=current_user.id, comp_id=comp_id).first():
        flash('Du nimmst bereits teil.', 'info')
    else:
        p = Participant(user_id=current_user.id, comp_id=comp_id)
        db.session.add(p)
        db.session.commit()
        flash('Du hast erfolgreich teilgenommen.', 'success')
    return redirect(url_for('user.dashboard'))

@user_bp.route('/competition/<int:comp_id>/leave')
@login_required
def leave_competition(comp_id):
    comp = Competition.query.get_or_404(comp_id)
    if comp.status != 'created':
        flash('Du kannst nicht mehr austreten, der Wettbewerb läuft bereits.', 'danger')
        return redirect(url_for('user.dashboard'))
    part = Participant.query.filter_by(user_id=current_user.id, comp_id=comp_id).first()
    if part:
        db.session.delete(part)
        db.session.commit()
        flash('Du bist ausgetreten.', 'success')
    return redirect(url_for('user.dashboard'))

@user_bp.route('/competition/<int:comp_id>')
@login_required
def view_competition(comp_id):
    comp = Competition.query.get_or_404(comp_id)
    if not Participant.query.filter_by(user_id=current_user.id, comp_id=comp_id).first():
        flash('Du nimmst an diesem Wettbewerb nicht teil.', 'danger')
        return redirect(url_for('user.dashboard'))
    round = Round.query.filter_by(comp_id=comp_id).order_by(Round.round_num.desc()).first()
    place = None
    if round:
        place = Place.query.filter_by(round_id=round.id).filter(
            (Place.left_user_id == current_user.id) | (Place.right_user_id == current_user.id)
        ).first()
    return render_template('user/competition.html', comp=comp, round=round, place=place)

@user_bp.route('/place/<int:place_id>', methods=['GET', 'POST'])
@login_required
def enter_place(place_id):
    place = Place.query.get_or_404(place_id)
    if current_user.id not in (place.left_user_id, place.right_user_id):
        flash('Das ist nicht dein Platz.', 'danger')
        return redirect(url_for('user.dashboard'))
    opponent = place.right_user if place.left_user_id == current_user.id else place.left_user
    result = Result.query.filter_by(place_id=place.id, user_id=current_user.id).first()
    if not result:
        result = Result(place_id=place.id, user_id=current_user.id)
        db.session.add(result)
        db.session.commit()
    form = ResultForm()
    if form.validate_on_submit():
        result.fish_count = form.fish_count.data
        if 'photo' in request.files and request.files['photo'].filename:
            filename = save_photo(request.files['photo'], folder='catches')
            result.photo_path = filename
        result.confirmed = False
        result.dispute = False
        db.session.commit()
        flash('Ergebnis gespeichert. Bitte bestätigen, wenn du sicher bist.', 'success')
        return redirect(url_for('user.enter_place', place_id=place.id))
    return render_template('user/place.html', place=place, opponent=opponent, result=result, form=form)

@user_bp.route('/place/<int:place_id>/confirm')
@login_required
def confirm_result(place_id):
    place = Place.query.get_or_404(place_id)
    if current_user.id not in (place.left_user_id, place.right_user_id):
        flash('Zugriff verweigert.', 'danger')
        return redirect(url_for('user.dashboard'))
    result = Result.query.filter_by(place_id=place.id, user_id=current_user.id).first()
    if not result:
        flash('Kein Ergebnis vorhanden.', 'warning')
        return redirect(url_for('user.enter_place', place_id=place.id))
    result.confirmed = True
    db.session.commit()
    other_user_id = place.right_user_id if place.left_user_id == current_user.id else place.left_user_id
    other_result = Result.query.filter_by(place_id=place.id, user_id=other_user_id).first()
    if other_result and other_result.confirmed:
        if result.fish_count > other_result.fish_count:
            result.points_awarded = 3
            other_result.points_awarded = 0
        elif result.fish_count == other_result.fish_count:
            result.points_awarded = 1
            other_result.points_awarded = 1
        else:
            result.points_awarded = 0
            other_result.points_awarded = 3
        result.dispute = False
        other_result.dispute = False
        db.session.commit()
        flash('Ergebnis bestätigt und Punkte vergeben!', 'success')
    else:
        flash('Ergebnis bestätigt. Warte auf Bestätigung des Gegners.', 'info')
    return redirect(url_for('user.enter_place', place_id=place.id))

@user_bp.route('/competition/<int:comp_id>/scoreboard')
@login_required
def scoreboard(comp_id):
    comp = Competition.query.get_or_404(comp_id)
    if not current_user.is_admin and not Participant.query.filter_by(user_id=current_user.id, comp_id=comp_id).first():
        flash('Zugriff verweigert.', 'danger')
        return redirect(url_for('user.dashboard'))
    participants = comp.participants.all()
    scoreboard = []
    for p in participants:
        total = db.session.query(db.func.sum(Result.points_awarded)).join(Place).join(Round).filter(
            Round.comp_id == comp_id,
            Result.user_id == p.user_id
        ).scalar() or 0
        scoreboard.append({
            'user': p.user,
            'total_points': total
        })
    scoreboard.sort(key=lambda x: x['total_points'], reverse=True)
    return render_template('competition/scoreboard.html', comp=comp, scoreboard=scoreboard)
EOF

cat > routes/admin.py << 'EOF'
from flask import Blueprint, render_template, flash, redirect, url_for, request
from flask_login import login_required, current_user
from models import User, Competition, Participant, db, Round, Place, Result
from utils.decorators import admin_required
from forms.competition import CompetitionForm
from datetime import datetime
import random

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/admin')
@login_required
@admin_required
def dashboard():
    competitions = Competition.query.all()
    users_count = User.query.count()
    return render_template('admin/dashboard.html', competitions=competitions, users_count=users_count)

@admin_bp.route('/admin/competition/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_competition():
    form = CompetitionForm()
    if form.validate_on_submit():
        comp = Competition(
            name=form.name.data,
            zeit=form.zeit.data,
            ort=form.ort.data,
            plaetze=form.plaetze.data,
            max_teilnehmer=form.max_teilnehmer.data,
            beschreibung=form.beschreibung.data,
            regeln=form.regeln.data
        )
        db.session.add(comp)
        db.session.commit()
        flash('Wettbewerb erstellt.', 'success')
        return redirect(url_for('admin.dashboard'))
    return render_template('admin/competition_form.html', form=form)

@admin_bp.route('/admin/competition/<int:comp_id>')
@login_required
@admin_required
def manage_competition(comp_id):
    comp = Competition.query.get_or_404(comp_id)
    participants = comp.participants.all()
    rounds = comp.rounds.order_by(Round.round_num).all()
    return render_template('admin/manage_competition.html', comp=comp, participants=participants, rounds=rounds)

@admin_bp.route('/admin/competition/<int:comp_id>/start')
@login_required
@admin_required
def start_competition(comp_id):
    comp = Competition.query.get_or_404(comp_id)
    if comp.status != 'created':
        flash('Wettbewerb wurde bereits gestartet.', 'warning')
        return redirect(url_for('admin.manage_competition', comp_id=comp_id))
    participants = list(comp.participants.all())
    if len(participants) < 2:
        flash('Mindestens 2 Teilnehmer benötigt.', 'danger')
        return redirect(url_for('admin.manage_competition', comp_id=comp_id))
    round1 = Round(comp_id=comp.id, round_num=1, started=True)
    db.session.add(round1)
    db.session.flush()
    random.shuffle(participants)
    for i in range(comp.plaetze):
        left = participants[i*2].user if i*2 < len(participants) else None
        right = participants[i*2+1].user if i*2+1 < len(participants) else None
        place = Place(round_id=round1.id, place_num=i+1,
                      left_user_id=left.id if left else None,
                      right_user_id=right.id if right else None)
        db.session.add(place)
    comp.status = 'started'
    db.session.commit()
    flash('Wettbewerb gestartet. Runde 1 läuft.', 'success')
    return redirect(url_for('admin.manage_competition', comp_id=comp_id))

@admin_bp.route('/admin/round/<int:round_id>/rotate')
@login_required
@admin_required
def rotate_round(round_id):
    round = Round.query.get_or_404(round_id)
    comp = round.competition
    next_num = round.round_num + 1
    if next_num > comp.plaetze:
        flash('Maximale Rundenzahl erreicht. Wettbewerb beenden?', 'warning')
        return redirect(url_for('admin.manage_competition', comp_id=comp.id))
    current_users = []
    for place in round.places:
        if place.left_user:
            current_users.append(place.left_user)
        if place.right_user:
            current_users.append(place.right_user)
    if current_users:
        first = current_users.pop(0)
        current_users.append(first)
    new_round = Round(comp_id=comp.id, round_num=next_num, started=True)
    db.session.add(new_round)
    db.session.flush()
    idx = 0
    for i in range(comp.plaetze):
        left = current_users[idx] if idx < len(current_users) else None
        idx += 1
        right = current_users[idx] if idx < len(current_users) else None
        idx += 1
        place = Place(round_id=new_round.id, place_num=i+1,
                      left_user_id=left.id if left else None,
                      right_user_id=right.id if right else None)
        db.session.add(place)
    comp.status = 'ongoing'
    db.session.commit()
    flash(f'Runde {next_num} gestartet.', 'success')
    return redirect(url_for('admin.manage_competition', comp_id=comp.id))

@admin_bp.route('/admin/competition/<int:comp_id>/finish')
@login_required
@admin_required
def finish_competition(comp_id):
    comp = Competition.query.get_or_404(comp_id)
    comp.status = 'finished'
    db.session.commit()
    flash('Wettbewerb beendet.', 'success')
    return redirect(url_for('admin.manage_competition', comp_id=comp.id))

@admin_bp.route('/admin/competition/<int:comp_id>/user/<int:user_id>/results', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user_results(comp_id, user_id):
    comp = Competition.query.get_or_404(comp_id)
    user = User.query.get_or_404(user_id)
    if not Participant.query.filter_by(comp_id=comp_id, user_id=user_id).first():
        flash('Benutzer nimmt nicht an diesem Wettbewerb teil.', 'danger')
        return redirect(url_for('admin.manage_competition', comp_id=comp_id))
    results = Result.query.join(Place).join(Round).filter(
        Round.comp_id == comp_id,
        Result.user_id == user_id
    ).order_by(Round.round_num).all()
    if request.method == 'POST':
        for res in results:
            field_name = f'points_{res.id}'
            if field_name in request.form:
                try:
                    new_points = int(request.form[field_name])
                    res.points_awarded = new_points
                except:
                    pass
        db.session.commit()
        flash('Punkte aktualisiert.', 'success')
        return redirect(url_for('admin.edit_user_results', comp_id=comp_id, user_id=user_id))
    return render_template('admin/edit_results.html', comp=comp, user=user, results=results)
EOF

cat > routes/competition.py << 'EOF'
from flask import Blueprint

comp_bp = Blueprint('competition', __name__)
# Platzhalter
EOF

# ======================== ШАБЛОНЫ ========================

cat > templates/base.html << 'EOF'
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes">
    <title>Angelwettbewerb - {% block title %}Willkommen{% endblock %}</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(145deg, #0b3d5f 0%, #1b7a9e 100%);
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .glass-card {
            background: rgba(255,255,255,0.15);
            backdrop-filter: blur(8px);
            border-radius: 20px;
            border: 1px solid rgba(255,255,255,0.2);
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }
        .btn {
            @apply px-6 py-3 rounded-full font-semibold transition transform hover:scale-105 focus:outline-none inline-block;
        }
        .btn-primary {
            @apply bg-yellow-500 text-gray-900 hover:bg-yellow-400;
        }
        .btn-secondary {
            @apply bg-blue-600 text-white hover:bg-blue-500;
        }
        .btn-danger {
            @apply bg-red-600 text-white hover:bg-red-500;
        }
        .form-input {
            @apply w-full p-2 mb-2 text-black rounded;
            background-color: white !important;
            color: black !important;
        }
    </style>
</head>
<body class="text-white">
    <nav class="p-4 flex flex-wrap justify-between items-center">
        <a href="/" class="text-2xl font-bold"><i class="fas fa-fish"></i> Angelwettbewerb</a>
        <div class="space-x-2 mt-2 sm:mt-0">
            {% if current_user.is_authenticated %}
                <span>Hallo, {{ current_user.vorname }}</span>
                {% if current_user.is_admin %}
                    <a href="{{ url_for('admin.dashboard') }}" class="btn btn-secondary text-sm">Admin</a>
                {% else %}
                    <a href="{{ url_for('user.dashboard') }}" class="btn btn-secondary text-sm">Dashboard</a>
                {% endif %}
                <a href="{{ url_for('auth.logout') }}" class="btn btn-primary text-sm">Abmelden</a>
            {% else %}
                <a href="{{ url_for('auth.login') }}" class="btn btn-secondary text-sm">Anmelden</a>
                <a href="{{ url_for('auth.register') }}" class="btn btn-primary text-sm">Registrieren</a>
            {% endif %}
        </div>
    </nav>
    <main class="container mx-auto p-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="glass-card p-4 mb-4 {% if category == 'danger' %}bg-red-500/30{% elif category == 'success' %}bg-green-500/30{% else %}bg-blue-500/30{% endif %}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </main>
</body>
</html>
EOF

cat > templates/index.html << 'EOF'
{% extends "base.html" %}
{% block title %}Startseite{% endblock %}
{% block content %}
<div class="glass-card p-8 text-center max-w-2xl mx-auto">
    <h1 class="text-4xl font-bold mb-4">Willkommen beim Angelwettbewerb</h1>
    <i class="fas fa-water text-6xl mb-4 text-blue-300"></i>
    <p class="text-lg">Verwalte deine Angelwettbewerbe einfach und elegant.</p>
    <div class="mt-8">
        <a href="{{ url_for('auth.register') }}" class="btn btn-primary text-lg">Jetzt registrieren</a>
    </div>
</div>
{% endblock %}
EOF

cat > templates/auth/login.html << 'EOF'
{% extends "base.html" %}
{% block title %}Anmelden{% endblock %}
{% block content %}
<div class="glass-card p-8 max-w-md mx-auto">
    <h2 class="text-2xl mb-4">Anmelden</h2>
    <form method="post">
        {{ form.hidden_tag() }}
        <div>
            {{ form.email.label(class="block mb-1") }}
            {{ form.email(class="form-input") }}
        </div>
        <div>
            {{ form.password.label(class="block mb-1") }}
            {{ form.password(class="form-input") }}
        </div>
        <div class="flex items-center mb-4">
            {{ form.admin_mode() }} {{ form.admin_mode.label(class="ml-2") }}
        </div>
        {{ form.submit(class="btn btn-primary w-full") }}
    </form>
</div>
{% endblock %}
EOF

cat > templates/auth/register.html << 'EOF'
{% extends "base.html" %}
{% block title %}Registrieren{% endblock %}
{% block content %}
<div class="glass-card p-8 max-w-md mx-auto">
    <h2 class="text-2xl mb-4">Registrieren</h2>
    <form method="post">
        {{ form.hidden_tag() }}
        <div>
            {{ form.vorname.label(class="block mb-1") }}
            {{ form.vorname(class="form-input") }}
        </div>
        <div>
            {{ form.nachname.label(class="block mb-1") }}
            {{ form.nachname(class="form-input") }}
        </div>
        <div>
            {{ form.telefon.label(class="block mb-1") }}
            {{ form.telefon(class="form-input", placeholder="+491761234567") }}
        </div>
        <div>
            {{ form.email.label(class="block mb-1") }}
            {{ form.email(class="form-input") }}
        </div>
        <div>
            {{ form.password.label(class="block mb-1") }}
            {{ form.password(class="form-input") }}
        </div>
        <div>
            {{ form.password2.label(class="block mb-1") }}
            {{ form.password2(class="form-input") }}
        </div>
        {{ form.submit(class="btn btn-primary w-full") }}
    </form>
</div>
{% endblock %}
EOF

cat > templates/user/dashboard.html << 'EOF'
{% extends "base.html" %}
{% block title %}Dashboard{% endblock %}
{% block content %}
<div class="glass-card p-8">
    <h1 class="text-3xl mb-4">Mein Dashboard</h1>
    <p>Willkommen, {{ current_user.vorname }}!</p>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
        {% for comp in competitions %}
            <div class="glass-card p-4">
                <h3 class="text-xl">{{ comp.name }}</h3>
                <p><i class="far fa-calendar-alt"></i> {{ comp.zeit.strftime('%d.%m.%Y %H:%M') }}</p>
                <p><i class="fas fa-map-marker-alt"></i> {{ comp.ort }}</p>
                <p>Teilnehmer: {{ comp.participants.count() }}/{{ comp.max_teilnehmer }}</p>
                {% if comp.id in participated_ids %}
                    {% if comp.status == 'created' %}
                        <a href="{{ url_for('user.leave_competition', comp_id=comp.id) }}" class="btn btn-danger mt-2">Abmelden</a>
                    {% else %}
                        <a href="{{ url_for('user.view_competition', comp_id=comp.id) }}" class="btn btn-primary mt-2">Zum Wettbewerb</a>
                    {% endif %}
                {% else %}
                    {% if comp.status == 'created' and comp.participants.count() < comp.max_teilnehmer %}
                        <a href="{{ url_for('user.join_competition', comp_id=comp.id) }}" class="btn btn-primary mt-2">Teilnehmen</a>
                    {% else %}
                        <span class="text-gray-400">Nicht verfügbar</span>
                    {% endif %}
                {% endif %}
            </div>
        {% endfor %}
    </div>
</div>
{% endblock %}
EOF

cat > templates/user/competition.html << 'EOF'
{% extends "base.html" %}
{% block title %}{{ comp.name }}{% endblock %}
{% block content %}
<div class="glass-card p-8">
    <h1 class="text-3xl mb-4">{{ comp.name }}</h1>
    <p><strong>Ort:</strong> {{ comp.ort }}</p>
    <p><strong>Zeit:</strong> {{ comp.zeit.strftime('%d.%m.%Y %H:%M') }}</p>
    <p><strong>Status:</strong> {{ comp.status }}</p>
    <div class="mt-4">
        <a href="{{ url_for('user.scoreboard', comp_id=comp.id) }}" class="btn btn-secondary">🏆 Rangliste</a>
    </div>
    {% if round %}
        <p><strong>Aktuelle Runde:</strong> {{ round.round_num }}</p>
        {% if place %}
            <p>Dein Platz: #{{ place.place_num }}</p>
            <a href="{{ url_for('user.enter_place', place_id=place.id) }}" class="btn btn-primary">Platz betreten</a>
        {% else %}
            <p>Du bist in dieser Runde keinem Platz zugeordnet.</p>
        {% endif %}
    {% else %}
        <p>Der Wettbewerb hat noch nicht begonnen.</p>
    {% endif %}
</div>
{% endblock %}
EOF

cat > templates/user/place.html << 'EOF'
{% extends "base.html" %}
{% block title %}Platz {{ place.place_num }}{% endblock %}
{% block content %}
<div class="glass-card p-8 max-w-2xl mx-auto">
    <h1 class="text-3xl mb-4">Platz {{ place.place_num }}</h1>
    <div class="flex justify-around mb-6">
        <div class="text-center">
            <img src="{{ url_for('static', filename='uploads/' + (place.left_user.photo_path if place.left_user else 'default_avatar.png')) }}" class="w-24 h-24 rounded-full mx-auto">
            <p>{{ place.left_user.full_name() if place.left_user else 'Frei' }}</p>
        </div>
        <div class="text-center">
            <img src="{{ url_for('static', filename='uploads/' + (place.right_user.photo_path if place.right_user else 'default_avatar.png')) }}" class="w-24 h-24 rounded-full mx-auto">
            <p>{{ place.right_user.full_name() if place.right_user else 'Frei' }}</p>
        </div>
    </div>
    <div class="border-t border-white/20 pt-4">
        <h2 class="text-xl mb-2">Ergebnis eingeben</h2>
        <form method="post" enctype="multipart/form-data">
            {{ form.hidden_tag() }}
            <div>
                {{ form.fish_count.label(class="block mb-1") }}
                {{ form.fish_count(class="form-input") }}
            </div>
            <div>
                <label class="block mb-1">Foto (optional)</label>
                <input type="file" name="photo" accept="image/*" class="form-input">
            </div>
            {{ form.submit(class="btn btn-primary") }}
        </form>
        {% if result %}
            <p class="mt-4">Aktueller Eintrag: {{ result.fish_count }} Fische</p>
            {% if result.confirmed %}
                <p class="text-green-400">Bestätigt ✓</p>
            {% else %}
                <a href="{{ url_for('user.confirm_result', place_id=place.id) }}" class="btn btn-secondary mt-2">Bestätigen</a>
            {% endif %}
        {% endif %}
    </div>
</div>
{% endblock %}
EOF

cat > templates/admin/dashboard.html << 'EOF'
{% extends "base.html" %}
{% block title %}Admin Dashboard{% endblock %}
{% block content %}
<div class="glass-card p-8">
    <h1 class="text-3xl mb-4">Admin Dashboard</h1>
    <p>Registrierte Benutzer: {{ users_count }}</p>
    <div class="mt-4">
        <a href="{{ url_for('admin.new_competition') }}" class="btn btn-primary">Neuen Wettbewerb erstellen</a>
    </div>
    <h2 class="text-2xl mt-6 mb-2">Wettbewerbe</h2>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        {% for comp in competitions %}
            <div class="glass-card p-4">
                <h3>{{ comp.name }}</h3>
                <p>Status: {{ comp.status }}</p>
                <p>Teilnehmer: {{ comp.participants.count() }}/{{ comp.max_teilnehmer }}</p>
                <a href="{{ url_for('admin.manage_competition', comp_id=comp.id) }}" class="btn btn-secondary mt-2">Verwalten</a>
            </div>
        {% endfor %}
    </div>
</div>
{% endblock %}
EOF

cat > templates/admin/competition_form.html << 'EOF'
{% extends "base.html" %}
{% block title %}Wettbewerb erstellen{% endblock %}
{% block content %}
<div class="glass-card p-8 max-w-2xl mx-auto">
    <h1 class="text-3xl mb-4">Neuen Wettbewerb erstellen</h1>
    <form method="post">
        {{ form.hidden_tag() }}
        <div>
            {{ form.name.label(class="block mb-1") }}
            {{ form.name(class="form-input") }}
        </div>
        <div>
            {{ form.zeit.label(class="block mb-1") }}
            {{ form.zeit(class="form-input", placeholder="2025-06-01 14:00") }}
        </div>
        <div>
            {{ form.ort.label(class="block mb-1") }}
            {{ form.ort(class="form-input") }}
        </div>
        <div>
            {{ form.plaetze.label(class="block mb-1") }}
            {{ form.plaetze(class="form-input") }}
        </div>
        <div>
            {{ form.max_teilnehmer.label(class="block mb-1") }}
            {{ form.max_teilnehmer(class="form-input") }}
        </div>
        <div>
            {{ form.beschreibung.label(class="block mb-1") }}
            {{ form.beschreibung(class="form-input", rows=3) }}
        </div>
        <div>
            {{ form.regeln.label(class="block mb-1") }}
            {{ form.regeln(class="form-input", rows=3) }}
        </div>
        {{ form.submit(class="btn btn-primary") }}
    </form>
</div>
{% endblock %}
EOF

cat > templates/admin/manage_competition.html << 'EOF'
{% extends "base.html" %}
{% block title %}{{ comp.name }} verwalten{% endblock %}
{% block content %}
<div class="glass-card p-8">
    <h1 class="text-3xl mb-4">{{ comp.name }}</h1>
    <p>Status: {{ comp.status }}</p>
    <div class="mt-4 space-x-2">
        {% if comp.status == 'created' %}
            <a href="{{ url_for('admin.start_competition', comp_id=comp.id) }}" class="btn btn-primary">Wettbewerb starten</a>
        {% endif %}
        {% if comp.status == 'ongoing' or comp.status == 'started' %}
            <a href="{{ url_for('admin.finish_competition', comp_id=comp.id) }}" class="btn btn-danger">Beenden</a>
        {% endif %}
    </div>
    <h2 class="text-2xl mt-6">Teilnehmer ({{ participants|length }})</h2>
    <a href="{{ url_for('user.scoreboard', comp_id=comp.id) }}" class="btn btn-primary mb-2">🏆 Rangliste anzeigen</a>
    <ul class="list-disc pl-5">
        {% for p in participants %}
            <li>{{ p.user.full_name() }} ({{ p.user.email }})</li>
        {% endfor %}
    </ul>
    <h2 class="text-2xl mt-6">Runden</h2>
    {% for r in rounds %}
        <div class="border-t border-white/20 py-2">
            <h3>Runde {{ r.round_num }}</h3>
            {% if r.started and not r.finished %}
                <a href="{{ url_for('admin.rotate_round', round_id=r.id) }}" class="btn btn-secondary">Nächste Runde</a>
            {% endif %}
            <div class="grid grid-cols-2 gap-2 mt-2">
                {% for place in r.places %}
                    <div class="bg-white/10 p-2 rounded">
                        Platz {{ place.place_num }}: {{ place.left_user.full_name() if place.left_user else 'Frei' }} vs {{ place.right_user.full_name() if place.right_user else 'Frei' }}
                    </div>
                {% endfor %}
            </div>
        </div>
    {% endfor %}
</div>
{% endblock %}
EOF

cat > templates/admin/edit_results.html << 'EOF'
{% extends "base.html" %}
{% block title %}Punkte bearbeiten - {{ user.full_name() }}{% endblock %}
{% block content %}
<div class="glass-card p-8">
    <h1 class="text-3xl mb-4">Punkte bearbeiten: {{ user.full_name() }}</h1>
    <h2 class="text-xl mb-2">{{ comp.name }}</h2>
    <a href="{{ url_for('admin.manage_competition', comp_id=comp.id) }}" class="btn btn-secondary mb-4">← Zurück zur Übersicht</a>
    
    <form method="post">
        <div class="overflow-x-auto">
            <table class="min-w-full bg-white/10 rounded-lg">
                <thead>
                    <tr class="border-b border-white/20">
                        <th class="p-3">Runde</th>
                        <th class="p-3">Platz</th>
                        <th class="p-3">Gegner</th>
                        <th class="p-3">Fische</th>
                        <th class="p-3">Punkte (bearbeitbar)</th>
                    </tr>
                </thead>
                <tbody>
                    {% for res in results %}
                    <tr class="border-b border-white/10">
                        <td class="p-3">{{ res.place.round.round_num }}</td>
                        <td class="p-3">{{ res.place.place_num }}</td>
                        <td class="p-3">
                            {% if res.place.left_user_id == user.id %}
                                {{ res.place.right_user.full_name() if res.place.right_user else 'Frei' }}
                            {% else %}
                                {{ res.place.left_user.full_name() if res.place.left_user else 'Frei' }}
                            {% endif %}
                        </td>
                        <td class="p-3">{{ res.fish_count }}</td>
                        <td class="p-3">
                            <input type="number" name="points_{{ res.id }}" value="{{ res.points_awarded }}" class="form-input w-20">
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        <button type="submit" class="btn btn-primary mt-4">Speichern</button>
    </form>
</div>
{% endblock %}
EOF

cat > templates/competition/scoreboard.html << 'EOF'
{% extends "base.html" %}
{% block title %}Rangliste - {{ comp.name }}{% endblock %}
{% block content %}
<div class="glass-card p-8">
    <h1 class="text-3xl mb-4">{{ comp.name }} – Rangliste</h1>
    <a href="javascript:history.back()" class="btn btn-secondary mb-4">← Zurück</a>
    
    <div class="overflow-x-auto">
        <table class="min-w-full bg-white/10 rounded-lg">
            <thead>
                <tr class="border-b border-white/20">
                    <th class="p-3 text-left">Platz</th>
                    <th class="p-3 text-left">Teilnehmer</th>
                    <th class="p-3 text-left">Gesamtpunkte</th>
                    {% if current_user.is_admin %}
                    <th class="p-3 text-left">Aktionen</th>
                    {% endif %}
                </tr>
            </thead>
            <tbody>
                {% for entry in scoreboard %}
                <tr class="border-b border-white/10 hover:bg-white/5">
                    <td class="p-3">{{ loop.index }}</td>
                    <td class="p-3">{{ entry.user.full_name() }}</td>
                    <td class="p-3 font-bold">{{ entry.total_points }}</td>
                    {% if current_user.is_admin %}
                    <td class="p-3">
                        <a href="{{ url_for('admin.edit_user_results', comp_id=comp.id, user_id=entry.user.id) }}" class="btn btn-secondary text-sm">Punkte bearbeiten</a>
                    </td>
                    {% endif %}
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>
{% endblock %}
EOF

cat > templates/errors/404.html << 'EOF'
{% extends "base.html" %}
{% block title %}Seite nicht gefunden{% endblock %}
{% block content %}
<div class="glass-card p-8 text-center">
    <h1 class="text-6xl mb-4">404</h1>
    <p class="text-xl">Die gesuchte Seite existiert leider nicht.</p>
    <a href="/" class="btn btn-primary mt-4">Zurück zur Startseite</a>
</div>
{% endblock %}
EOF

cat > templates/errors/500.html << 'EOF'
{% extends "base.html" %}
{% block title %}Interner Fehler{% endblock %}
{% block content %}
<div class="glass-card p-8 text-center">
    <h1 class="text-6xl mb-4">500</h1>
    <p class="text-xl">Ein interner Fehler ist aufgetreten. Bitte versuche es später erneut.</p>
    <a href="/" class="btn btn-primary mt-4">Zurück zur Startseite</a>
</div>
{% endblock %}
EOF

cat > templates/impressum.html << 'EOF'
{% extends "base.html" %}
{% block title %}Impressum{% endblock %}
{% block content %}
<div class="glass-card p-8 max-w-2xl mx-auto">
    <h1 class="text-3xl mb-4">Impressum</h1>
    <p>Angaben gemäß §5 TMG</p>
    <p>Max Mustermann<br>
    Musterstraße 1<br>
    12345 Musterstadt</p>
    <p>Kontakt: info@angelwettbewerb.local</p>
</div>
{% endblock %}
EOF

# ======================== СИД БАЗЫ ДАННЫХ ========================

cat > seed.py << 'EOF'
from app import create_app, db
from models import User, Competition, Participant
from datetime import datetime, timedelta
import random

app = create_app()
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email='admin@example.com').first():
        admin = User(
            vorname='Admin',
            nachname='User',
            telefon='+4915112345678',
            email='admin@example.com',
            is_admin=True,
            email_confirmed=True
        )
        admin.set_password('admin123')
        db.session.add(admin)

    names = [
        ('Anna', 'Schmidt'), ('Bernd', 'Müller'), ('Clara', 'Fischer'),
        ('Dieter', 'Weber'), ('Erika', 'Meyer'), ('Frank', 'Wagner'),
        ('Gabi', 'Becker'), ('Hans', 'Hoffmann'), ('Inge', 'Schäfer'),
        ('Jürgen', 'Koch'), ('Karin', 'Richter'), ('Lars', 'Klein'),
        ('Monika', 'Wolf'), ('Norbert', 'Schröder'), ('Olga', 'Neumann'),
        ('Peter', 'Schwarz'), ('Quirin', 'Zimmermann'), ('Rita', 'Braun'),
        ('Stefan', 'Krüger')
    ]
    for i, (vorname, nachname) in enumerate(names, start=1):
        email = f'user{i}@example.com'
        if not User.query.filter_by(email=email).first():
            user = User(
                vorname=vorname,
                nachname=nachname,
                telefon=f'+49176{i:07d}',
                email=email,
                is_admin=False,
                email_confirmed=True
            )
            user.set_password('user123')
            db.session.add(user)

    db.session.commit()

    comp = Competition.query.filter_by(name='Test-Turnier').first()
    if not comp:
        comp = Competition(
            name='Test-Turnier',
            zeit=datetime.now() + timedelta(hours=1),
            ort='See am Wald',
            plaetze=10,
            max_teilnehmer=20,
            beschreibung='Ein spannendes Angelturnier für alle.',
            regeln='Jeder angelt fair!',
            status='created'
        )
        db.session.add(comp)
        db.session.commit()

        users = User.query.filter_by(is_admin=False).all()
        for user in users:
            participant = Participant(user_id=user.id, comp_id=comp.id)
            db.session.add(participant)
        db.session.commit()

    print("Datenbank initialisiert und mit Testdaten befüllt.")
EOF

# ======================== ЗАПУСК ========================

echo "🗄️ Initialisiere Datenbank..."
python seed.py

echo "✅ Installation abgeschlossen!"
echo "🚀 Starte Server..."
export FLASK_APP=app.py
export FLASK_ENV=development
flask run --host=0.0.0.0 --port=5000
