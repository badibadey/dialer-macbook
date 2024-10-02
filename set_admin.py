from app import db, User, app

# Uruchomienie skryptu w kontekście aplikacji Flask
with app.app_context():
    # Znajdź użytkownika o podanym emailu
    user = User.query.filter_by(email='adrian@ivorylab.pl').first()

    if user:
        # Ustaw is_admin na True
        user.is_admin = True
        db.session.commit()
        print(f"User {user.email} is now an admin.")
    else:
        print("User not found.")
