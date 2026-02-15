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
    self_claim = db.Column(db.Integer, default=0)          # сколько поймал сам
    opponent_claim = db.Column(db.Integer, default=0)      # сколько, по мнению игрока, поймал соперник
    fish_count = db.Column(db.Integer, default=0)          # для совместимости (дублирует self_claim)
    confirmed = db.Column(db.Boolean, default=False)
    photo_path = db.Column(db.String(256))
    dispute = db.Column(db.Boolean, default=False)
    points_awarded = db.Column(db.Integer, default=0)
    user = db.relationship('User')

class SocialLink(db.Model):
    __tablename__ = 'social_links'
    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(50), unique=True, nullable=False)
    url = db.Column(db.String(200), nullable=False)
    active = db.Column(db.Boolean, default=True)
