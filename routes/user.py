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
    # Wenn Punkte bereits vergeben, keine Bearbeitung mehr
    if result.points_awarded > 0:
        flash('Die Ergebnisse wurden bereits bestätigt.', 'info')
        form = None
    else:
        form = ResultForm()
        if form.validate_on_submit():
            result.self_claim = form.fish_count.data
            result.opponent_claim = form.opponent_fish.data
            result.fish_count = result.self_claim
            result.confirmed = False
            result.dispute = False
            db.session.commit()
            flash('Ergebnis gespeichert. Bitte bestätigen, wenn du sicher bist.', 'success')
            return redirect(url_for('user.enter_place', place_id=place.id))
    opp_result = Result.query.filter_by(place_id=place.id, user_id=opponent.id).first() if opponent else None
    results_dict = {current_user.id: result}
    if opponent:
        results_dict[opponent.id] = opp_result
    return render_template('user/place.html', place=place, opponent=opponent, result=result, form=form, results=results_dict)

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
    
    # Falls bereits Punkte vergeben, nichts tun
    if result.points_awarded > 0:
        flash('Ergebnisse wurden bereits bestätigt.', 'info')
        return redirect(url_for('user.enter_place', place_id=place.id))
    
    # Eigenes Ergebnis bestätigen
    result.confirmed = True
    db.session.commit()
    
    other_user_id = place.right_user_id if place.left_user_id == current_user.id else place.left_user_id
    other_result = Result.query.filter_by(place_id=place.id, user_id=other_user_id).first()
    
    if other_result and other_result.confirmed:
        # Beide haben bestätigt – vergleichen
        if (result.self_claim == other_result.opponent_claim and
            result.opponent_claim == other_result.self_claim):
            # Übereinstimmung – Punkte vergeben
            if result.self_claim > other_result.self_claim:
                result.points_awarded = 3
                other_result.points_awarded = 0
            elif result.self_claim == other_result.self_claim:
                result.points_awarded = 1
                other_result.points_awarded = 1
            else:
                result.points_awarded = 0
                other_result.points_awarded = 3
            result.dispute = False
            other_result.dispute = False
            result.fish_count = result.self_claim
            other_result.fish_count = other_result.self_claim
            db.session.commit()
            flash('Ergebnisse stimmen überein! Punkte wurden vergeben.', 'success')
        else:
            # Keine Übereinstimmung – Bestätigungen zurücksetzen
            result.confirmed = False
            other_result.confirmed = False
            result.dispute = True
            other_result.dispute = True
            db.session.commit()
            flash('Die eingegebenen Fische stimmen nicht überein. Bitte beide Teilnehmer überprüfen und erneut eingeben.', 'danger')
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

@user_bp.route('/competition/<int:comp_id>/lake')
@login_required
def lake_view(comp_id):
    comp = Competition.query.get_or_404(comp_id)
    if not Participant.query.filter_by(user_id=current_user.id, comp_id=comp_id).first():
        flash('Zugriff verweigert.', 'danger')
        return redirect(url_for('user.dashboard'))
    current_round = comp.rounds.order_by(Round.round_num.desc()).first()
    if not current_round:
        flash('Keine Runde gefunden.', 'warning')
        return redirect(url_for('user.view_competition', comp_id=comp.id))
    places = current_round.places.order_by(Place.place_num).all()
    # Sammle Ergebnisse
    results_dict = {}
    for place in places:
        for user_id in [place.left_user_id, place.right_user_id]:
            if user_id:
                res = Result.query.filter_by(place_id=place.id, user_id=user_id).first()
                if res:
                    results_dict[(place.id, user_id)] = res
    return render_template('competition/lake_view.html', comp=comp, current_round=current_round, places=places, results_dict=results_dict)
