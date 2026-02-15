# Angelwettbewerb – Plattform für Angelwettbewerbe

Eine vollständige Webanwendung zur Verwaltung von Angelwettbewerben, entwickelt mit Flask, SQLite und Tailwind CSS. Läuft auf Termux (Android) und kann einfach auf einen Server migriert werden.

## Funktionen

- **Benutzerverwaltung**: Registrierung, Login (User/Admin), Profilbilder
- **Admin-Bereich**:
  - Wettbewerbe erstellen, bearbeiten, löschen
  - Teilnehmer manuell hinzufügen/entfernen
  - Runden verwalten (Start, Rotation, Beenden)
  - Ergebnisse editieren (auch nach Bestätigung)
  - Social-Media-Links konfigurieren
- **User-Bereich**:
  - Anstehende Wettbewerbe anzeigen, teilnehmen, austreten
  - Platz betreten: eigene Fänge und Schätzung des Gegners eingeben
  - Bestätigungslogik mit Punktevergabe (3/1/0) bei Übereinstimmung
  - Gesamtansicht (See) mit farblicher Statusanzeige
  - Rangliste mit Punkten
- **Rechtliches**: Impressum (gemäß §5 DDG), Datenschutzerklärung, Cookie-Hinweis
- **Design**: Responsiv, Glas-Effekt, Font Awesome Icons, Tailwind CSS
- **Deutsche Lokalisierung**

## Technologie-Stack

- Backend: Flask, SQLite, Flask-Login, Flask-WTF
- Frontend: Tailwind CSS, Font Awesome, Jinja2
- Deployment: Termux (Android) / Gunicorn (für Produktion)

## Installation (Termux)

```bash
pkg update && pkg upgrade -y
pkg install python clang libjpeg-turbo libffi openssl git
git clone https://github.com/deinusername/angelwettbewerb.git
cd angelwettbewerb
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python seed.py   # Testdaten einspielen
flask run --host=0.0.0.0 --port=5000

**requirements.txt** erstellen (alle Abhängigkeiten für einfache Installation):

```bash
cat > requirements.txt << 'EOF'
Flask
Flask-SQLAlchemy
Flask-WTF
Flask-Login
Flask-Migrate
Flask-Mail
email-validator
Werkzeug
Pillow
python-dotenv
alembic
