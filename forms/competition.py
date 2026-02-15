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
    fish_count = IntegerField('Deine gefangenen Fische', validators=[DataRequired(), NumberRange(min=0)], default=0)
    opponent_fish = IntegerField('Fische des Gegners (deine Schätzung)', validators=[DataRequired(), NumberRange(min=0)], default=0)
    submit = SubmitField('Speichern')
