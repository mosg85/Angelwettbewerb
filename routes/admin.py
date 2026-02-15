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

    # Prüfen, ob alle Ergebnisse bestätigt sind
    places = round.places.all()
    incomplete = []
    for place in places:
        if place.left_user_id:
            left_result = Result.query.filter_by(place_id=place.id, user_id=place.left_user_id).first()
            if not left_result or not left_result.confirmed:
                name = place.left_user.full_name() if place.left_user else "Unbekannt"
                incomplete.append(f"Platz {place.place_num}: {name} (links)")
        if place.right_user_id:
            right_result = Result.query.filter_by(place_id=place.id, user_id=place.right_user_id).first()
            if not right_result or not right_result.confirmed:
                name = place.right_user.full_name() if place.right_user else "Unbekannt"
                incomplete.append(f"Platz {place.place_num}: {name} (rechts)")

    if incomplete:
        flash("Folgende Teilnehmer haben ihre Ergebnisse noch nicht bestätigt:", "warning")
        for msg in incomplete:
            flash(msg, "warning")
        return redirect(url_for('admin.manage_competition', comp_id=comp.id))

    next_num = round.round_num + 1
    if next_num > comp.plaetze:
        flash('Maximale Rundenzahl erreicht. Wettbewerb beenden?', 'warning')
        return redirect(url_for('admin.manage_competition', comp_id=comp.id))

    # Проверка на дубликат следующего раунда
    existing_next = Round.query.filter_by(comp_id=comp.id, round_num=next_num).first()
    if existing_next:
        flash(f'Runde {next_num} existiert bereits.', 'warning')
        return redirect(url_for('admin.manage_competition', comp_id=comp.id))

    # Помечаем текущий раунд как завершённый
    round.finished = True
    db.session.commit()

    current_users = []
    for place in round.places:
        if place.left_user:
            current_users.append(place.left_user)
        if place.right_user:
            current_users.append(place.right_user)

    if current_users:
        first = current_users.pop(0)
        current_users.append(first)

    new_round = Round(comp_id=comp.id, round_num=next_num, started=True, finished=False)
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
    return redirect(url_for('admin.manage_competition', comp_id=comp_id))

@admin_bp.route('/admin/competition/<int:comp_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_competition(comp_id):
    comp = Competition.query.get_or_404(comp_id)
    db.session.delete(comp)
    db.session.commit()
    flash('Wettbewerb wurde gelöscht.', 'success')
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/admin/competition/<int:comp_id>/add_participant', methods=['GET', 'POST'])
@login_required
@admin_required
def add_participant(comp_id):
    comp = Competition.query.get_or_404(comp_id)
    if comp.status != 'created':
        flash('Teilnehmer können nur vor dem Start hinzugefügt werden.', 'warning')
        return redirect(url_for('admin.manage_competition', comp_id=comp_id))
    from models import User
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Benutzer mit dieser Email nicht gefunden.', 'danger')
            return redirect(url_for('admin.add_participant', comp_id=comp_id))
        existing = Participant.query.filter_by(comp_id=comp_id, user_id=user.id).first()
        if existing:
            flash('Benutzer nimmt bereits teil.', 'warning')
            return redirect(url_for('admin.manage_competition', comp_id=comp_id))
        if comp.participants.count() >= comp.max_teilnehmer:
            flash('Maximale Teilnehmerzahl erreicht.', 'danger')
            return redirect(url_for('admin.manage_competition', comp_id=comp_id))
        part = Participant(user_id=user.id, comp_id=comp_id)
        db.session.add(part)
        db.session.commit()
        flash(f'{user.full_name()} wurde hinzugefügt.', 'success')
        return redirect(url_for('admin.manage_competition', comp_id=comp_id))
    return render_template('admin/add_participant.html', comp=comp)

@admin_bp.route('/admin/competition/<int:comp_id>/remove_participant/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def remove_participant(comp_id, user_id):
    comp = Competition.query.get_or_404(comp_id)
    part = Participant.query.filter_by(comp_id=comp_id, user_id=user_id).first()
    if not part:
        flash('Teilnehmer nicht gefunden.', 'danger')
        return redirect(url_for('admin.manage_competition', comp_id=comp_id))
    db.session.delete(part)
    db.session.commit()
    flash('Teilnehmer entfernt.', 'success')
    return redirect(url_for('admin.manage_competition', comp_id=comp_id))

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

@admin_bp.route('/admin/competition/<int:comp_id>/lake')
@login_required
@admin_required
def lake_view(comp_id):
    comp = Competition.query.get_or_404(comp_id)
    current_round = comp.rounds.order_by(Round.round_num.desc()).first()
    if not current_round:
        flash('Keine Runde gefunden.', 'warning')
        return redirect(url_for('admin.manage_competition', comp_id=comp.id))
    places = current_round.places.order_by(Place.place_num).all()
    # Собираем результаты для всех мест
    results_dict = {}
    for place in places:
        for user_id in [place.left_user_id, place.right_user_id]:
            if user_id:
                res = Result.query.filter_by(place_id=place.id, user_id=user_id).first()
                if res:
                    results_dict[(place.id, user_id)] = res
    return render_template('competition/lake_view.html', comp=comp, current_round=current_round, places=places, results_dict=results_dict)

@admin_bp.route('/admin/place/<int:place_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_place(place_id):
    place = Place.query.get_or_404(place_id)
    comp = place.round.competition
    results = {}
    if place.left_user:
        res = Result.query.filter_by(place_id=place.id, user_id=place.left_user.id).first()
        if not res:
            res = Result(place_id=place.id, user_id=place.left_user.id)
            db.session.add(res)
            db.session.commit()
        results[place.left_user.id] = res
    if place.right_user:
        res = Result.query.filter_by(place_id=place.id, user_id=place.right_user.id).first()
        if not res:
            res = Result(place_id=place.id, user_id=place.right_user.id)
            db.session.add(res)
            db.session.commit()
        results[place.right_user.id] = res

    if request.method == 'POST':
        if place.left_user and results.get(place.left_user.id):
            r = results[place.left_user.id]
            r.fish_count = int(request.form.get('left_fish', 0))
            r.points_awarded = int(request.form.get('left_points', 0))
            r.confirmed = 'left_confirmed' in request.form
        if place.right_user and results.get(place.right_user.id):
            r = results[place.right_user.id]
            r.fish_count = int(request.form.get('right_fish', 0))
            r.points_awarded = int(request.form.get('right_points', 0))
            r.confirmed = 'right_confirmed' in request.form
        db.session.commit()
        flash('Ergebnisse aktualisiert.', 'success')
        return redirect(url_for('admin.lake_view', comp_id=comp.id))

    return render_template('admin/edit_place.html', place=place, comp=comp, results=results)

@admin_bp.route('/admin/social-links', methods=['GET', 'POST'])
@login_required
@admin_required
def social_links():
    from models import SocialLink
    links = SocialLink.query.all()
    
    if request.method == 'POST':
        for link in links:
            new_url = request.form.get(f'url_{link.platform}')
            active = request.form.get(f'active_{link.platform}') == 'on'
            link.url = new_url
            link.active = active
        db.session.commit()
        flash('Social-Links wurden aktualisiert.', 'success')
        return redirect(url_for('admin.social_links'))
    
    return render_template('admin/social_links.html', links=links)
