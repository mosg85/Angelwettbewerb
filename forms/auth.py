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
