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
