def get_social_links():
    """Holt alle aktiven Social Links aus der Datenbank"""
    # Import INSIDE the function to avoid circular import
    from models import SocialLink
    return SocialLink.query.filter_by(active=True).all()
