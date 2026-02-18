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
#            email_confirmed=True
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
 #               email_confirmed=True
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
