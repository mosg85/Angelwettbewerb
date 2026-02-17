from flask import Blueprint, render_template, flash, redirect, url_for, request
from flask_login import current_user

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/impressum')
def impressum():
    return render_template('impressum.html')

@main_bp.route('/send-message', methods=['POST'])
def send_message():
    name = request.form.get('name')
    flash(f'Danke {name}! Deine Nachricht wurde gesendet. Wir melden uns.', 'success')
    return redirect(url_for('main.impressum'))

@main_bp.route('/datenschutz')
def datenschutz():
    return render_template('datenschutz.html')
