from extensions import db
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    telefon = db.Column(db.String(20), unique=True, nullable=False)
    vorname = db.Column(db.String(50), nullable=False)
    nachname = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    profile_image = db.Column(db.String(255), default='default.png')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Competition(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='created')
    max_teilnehmer = db.Column(db.Integer, default=20)
    plaetze = db.Column(db.Integer, default=10)
    beschreibung = db.Column(db.Text)
    regeln = db.Column(db.Text)

class Participant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comp_id = db.Column(db.Integer, db.ForeignKey('competition.id'), nullable=False)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)

class Round(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    comp_id = db.Column(db.Integer, db.ForeignKey('competition.id'), nullable=False)
    round_num = db.Column(db.Integer, nullable=False)
    started = db.Column(db.Boolean, default=False)
    finished = db.Column(db.Boolean, default=False)

class Place(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    round_id = db.Column(db.Integer, db.ForeignKey('round.id'), nullable=False)
    place_num = db.Column(db.Integer, nullable=False)
    left_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    right_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    place_id = db.Column(db.Integer, db.ForeignKey('place.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fish_count = db.Column(db.Integer, default=0)
    self_claim = db.Column(db.Integer, default=None)
    opponent_claim = db.Column(db.Integer, default=None)
    points_awarded = db.Column(db.Integer, default=None)
    confirmed = db.Column(db.Boolean, default=False)
    dispute = db.Column(db.Boolean, default=False)

class SocialLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(50), nullable=False)
    url = db.Column(db.String(200), nullable=False)
    icon = db.Column(db.String(50))
    active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password, password)
