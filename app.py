import email
from subprocess import call
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, g, session, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import csv
import sqlite3
import os
import logging
import threading 
import dialer
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from sqlalchemy.orm import Session
import pytz

# Ustawienie domyślnej strefy czasowej na Warszawę
default_timezone = pytz.timezone('Europe/Warsaw')
#pytz.timezone = default_timezone

# Nadpisanie funkcji datetime.now(), aby zawsze zwracała czas w strefie czasowej Warszawy
original_now = datetime.now

def warsaw_now():
    warsaw_tz = pytz.timezone('Europe/Warsaw')
    return datetime.now(warsaw_tz)



app = Flask(__name__)
app.secret_key = 'supersecretkey'
DATABASE = 'database.db'  # Zdefiniowanie zmiennej DATABASE
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///new_database.db'
print(app.config['SQLALCHEMY_DATABASE_URI'])
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Archive(db.Model):
    __tablename__ = 'archive'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    bot_id = db.Column(db.Integer, nullable=False)
    group_name = db.Column(db.String(255), nullable=False)
    total_calls = db.Column(db.Integer, default=0)
    successful_calls = db.Column(db.Integer, default=0)
    failed_calls = db.Column(db.Integer, default=0)
    voicemail_calls = db.Column(db.Integer, default=0)
    cancelled_calls = db.Column(db.Integer, default=0)
    bye_status_calls = db.Column(db.Integer, default=0)
    call_ended_successfully = db.Column(db.Integer, default=0)  
    other_errors = db.Column(db.Integer, default=0)
    average_call_duration = db.Column(db.Float, default=0.0)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Archive {self.id}>'

logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

stats = {
    'total_calls': 0,
    'successful_calls': 0,
    'failed_calls': 0
}

contacts = []

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('User registered successfully.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            session['user_id'] = user.id  # Ustawienie user_id w sesji
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')


@app.route('/logout')
def logout():
        session.clear()
        flash('You have been logged out.')
        return redirect(url_for('login'))

@app.route('/admin')
@login_required
def admin_panel():
    if current_user.is_admin:
        users = User.query.all()
        return render_template('admin.html', users=users)
    else:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

# Edycja uzytkownika

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('admin_panel'))
    
    if request.method == 'POST':
        user.email = request.form['email']
        user.role = request.form['role']
        db.session.commit()
        flash('User updated successfully.', 'success')
        return redirect(url_for('admin_panel'))
    
    return render_template('edit_user.html', user=user)

    # Usuwanie uzytkownika

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('admin_panel'))

    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/')
@login_required
def index():
    return render_template('dashboard.html')

@app.route('/dashboard')
@login_required
def dashboard():
    stats = {
        'total_calls': 1000,
        'successful_calls': 600,
        'failed_calls': 150,
        'voicemail_calls': 50,
        'cancelled_calls': 100,
        'bye_status_calls': 70,
        'call_ended_successfully': 30,
        'other_errors': 100,
        'average_call_duration': 120
    }
    return render_template('dashboard.html', stats=stats)


@app.route('/archive')
@login_required
def archive_page():
    filter_date = request.args.get('filter_date')
    
    query = Archive.query.filter_by(user_id=current_user.id)
    
    if filter_date:
        try:
            filter_date = datetime.strptime(filter_date, '%Y-%m-%d').date()
            query = query.filter(db.func.date(Archive.date) == filter_date)
        except ValueError:
            flash('Nieprawidłowy format daty', 'error')
    
    archive_data = query.order_by(Archive.date.desc()).all()
    
    return render_template('archive.html', archive_data=archive_data, filter_date=filter_date)



@app.route('/dialer')
@login_required
def dialer_view():
    print("Stats:", stats)
    page = request.args.get('page', 1, type=int)
    contacts_per_page = 100
    start = (page - 1) * contacts_per_page
    end = start + contacts_per_page

    paginated_contacts = contacts[start:end]
    
    for i, contact in enumerate(paginated_contacts, start=start + 1):
        contact['number'] = i

    total_pages = (len(contacts) + contacts_per_page - 1) // contacts_per_page
    
    return render_template(
        'dialer.html', 
        stats=stats, 
        contacts=paginated_contacts,
        current_page=page,
        total_pages=total_pages
    )

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        logging.error('No file part in request')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        logging.error('No file selected for upload')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        load_contacts(filepath)
        logging.info(f'File {filename} uploaded successfully')
        return redirect(url_for('dialer_view'))
    else:
        flash('Allowed file types are csv')
        logging.error('Invalid file type uploaded')
        return redirect(request.url)

@app.route('/get_statuses')
def get_statuses():
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 100, type=int)
    status = request.args.get('status', '', type=str)
    reason = request.args.get('reason', '', type=str)

    filtered_contacts = contacts
    if status:
        filtered_contacts = [c for c in filtered_contacts if c['status'] == status]
    if reason:
        filtered_contacts = [c for c in filtered_contacts if reason.lower() in c['reason'].lower()]

    total_contacts = len(filtered_contacts)
    start = (page - 1) * page_size
    end = start + page_size

    paginated_contacts = filtered_contacts[start:end]

    return jsonify({
        'contacts': paginated_contacts,
        'total_contacts': total_contacts,
        'stats': stats
    })

def load_contacts(filepath):
    global contacts
    contacts = []
    with open(filepath, newline='') as csvfile:
        csvreader = csv.reader(csvfile)
        for row in csvreader:
            contact = {
                'phone': f"+{row[0].strip()}",
                'status': 'Not Called',
                'time': '',
                'reason': '',
                'duration': ''
            }
            contacts.append(contact)

@app.route('/add_contact', methods=['POST'])
def add_contact():
    phone = request.form['phone']
    if phone:
        contact = {
            'phone': f"+{phone.strip()}",
            'status': 'Not Called',
            'time': '',
            'reason': '',
            'duration': ''
        }
        contacts.append(contact)
        logging.info(f"Manually added contact: {contact}")
    return redirect(url_for('dialer_view'))

@app.route('/export_csv')
def export_csv():
    csv_path = 'static/uploads/contacts_export.csv'
    with open(csv_path, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        for contact in contacts:
            csvwriter.writerow([contact['phone'], contact['status'], contact['time'], contact['reason'], contact['duration']]) 
    return send_file(csv_path, as_attachment=True)

@app.route('/clear_all')
def clear_all():
    global contacts
    contacts = []
    logging.info("All contacts cleared")
    return jsonify({'message': 'All contacts cleared'})

@app.route('/remove_selected', methods=['POST'])
def remove_selected():
    global contacts
    data = request.get_json()
    phones_to_remove = data.get('phones', [])
    contacts = [contact for contact in contacts if contact['phone'] not in phones_to_remove]
    logging.info(f"Removed selected contacts: {phones_to_remove}")
    return jsonify({'message': 'Selected contacts removed'})

@app.route('/start_dialing')
def start_dialing():
    try:
        threading.Thread(target=dialer.start_dialing, args=(contacts, stats)).start()
        return jsonify({'message': 'Dialing started'})
    except Exception as e:
        logging.error(f"Error starting dialing: {e}")
        return jsonify({'message': 'Failed to start dialing', 'error': str(e)})

@app.route('/stop_dialing')
def stop_dialing():
    dialer.stop_dialing()
    return jsonify({'message': 'Dialing stopped'})

@app.route('/configuration')
@login_required
def configuration():
    return render_template('configuration.html')


@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if request.method == 'POST':
        # Logika tworzenia nowego użytkownika
        pass
    return render_template('create_user.html')

def collect_current_statistics():
    total_calls = len(contacts)
    successful_calls = len([c for c in contacts if c['status'] == 'Success'])
    failed_calls = len([c for c in contacts if c['status'] == 'Failed'])
    voicemail_calls = len([c for c in contacts if c['reason'] == 'voicemail detected'])
    cancelled_calls = len([c for c in contacts if c['reason'] == 'cancel'])
    bye_status_calls = len([c for c in contacts if c['reason'] == 'bye'])
    call_ended_successfully = len([c for c in contacts if c['reason'] == 'Call ended successfully'])  
    other_errors = len([c for c in contacts if c['reason'] not in ['voicemail detected', 'cancel', 'bye', 'Call ended successfully']])

    stats = {
        'total_calls': total_calls,
        'successful_calls': successful_calls,
        'failed_calls': failed_calls,
        'voicemail_calls': voicemail_calls,
        'cancelled_calls': cancelled_calls,
        'bye_status_calls': bye_status_calls,
        'call_ended_successfully': call_ended_successfully,  
        'other_errors': other_errors,
        'average_call_duration': sum([int(c['duration'].split()[0]) for c in contacts if 'seconds' in c['duration']]) / total_calls if total_calls > 0 else 0
    }

    return stats


@app.route('/archive_statistics', methods=['POST'])
@login_required
def archive_statistics_view():
    user_id = session.get('user_id')
    if not user_id:
        flash('User ID not found in session', 'danger')
        return redirect(url_for('dialer_view'))

    stats = collect_current_statistics()

    # Filtrujemy tylko wydzwonione kontakty (te, które nie mają reason "Not Called")
    called_contacts = [contact for contact in contacts if contact.get('reason') != 'Not Called']

    # Zakładam, że `bot_id` jest przechowywane w kontaktach i jest takie samo dla wszystkich połączeń
    bot_id = contacts[0].get('bot_id', 1) if contacts else 1  # Domyślnie ustawiamy na 1, jeśli brak danych

    group_name = current_user.username  # Używamy nazwy użytkownika jako group_name

    # Używamy funkcji warsaw_now() zamiast datetime.now()
    current_time = warsaw_now()

    # Zaokrąglamy average_call_duration do pełnej liczby
    average_call_duration = round(stats.get('average_call_duration', 0))

    archive_entry = Archive(
        user_id=user_id,
        bot_id=bot_id,  # Zapisujemy bot_id do archiwum
        group_name=group_name,
        total_calls=len(called_contacts),
        successful_calls=stats['successful_calls'],
        failed_calls=stats['failed_calls'],
        voicemail_calls=stats['voicemail_calls'],
        cancelled_calls=stats['cancelled_calls'],
        bye_status_calls=stats['bye_status_calls'],
        call_ended_successfully=stats['call_ended_successfully'], 
        other_errors=stats['other_errors'],
        average_call_duration=average_call_duration,
        date=current_time
    )
    db.session.add(archive_entry)
    db.session.commit()

    flash('Statistics have been archived successfully.', 'success')
    return redirect(url_for('dialer_view'))

def update_contact_status(conversation_id, status, reason, duration):
    contact = [c for c in contacts if c['conversation_id'] == conversation_id]
    if contact:
        contact['status'] = status
        contact['reason'] = reason
        contact['duration'] = duration

# Przykład funkcji pobierającej CSV
@app.route('/download_archive/<int:entry_id>')
@login_required
def download_single_entry(entry_id):
    entry = Archive.query.get_or_404(entry_id)
    
    csv_path = f'static/uploads/archive_{entry.id}.csv'
    with open(csv_path, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['Date', 'Total Calls', 'Successful Calls', 'Failed Calls', 'Voicemail Calls', 'Cancelled Calls', 'Bye Status Calls', 'Other Errors', 'Average Call Duration'])
        csvwriter.writerow([entry.date, entry.total_calls, entry.successful_calls, entry.failed_calls, entry.voicemail_calls, entry.cancelled_calls, entry.bye_status_calls, entry.other_errors, entry.average_call_duration])
    
    return send_file(csv_path, as_attachment=True)

@app.route('/delete_archive_entry/<int:entry_id>', methods=['POST'])
@login_required
def delete_archive_entry(entry_id):
    entry = Archive.query.get_or_404(entry_id)
    db.session.delete(entry)
    db.session.commit()
    flash('Entry deleted successfully.', 'success')
    return redirect(url_for('archive_page'))

@app.route('/api/dashboard_stats', methods=['GET'])
@login_required
def dashboard_stats():
    try:
        from datetime import datetime

        # Pobranie dzisiejszej daty
        today = datetime.utcnow().date()

        # Filtruj wpisy z archiwum na podstawie daty i aktualnego użytkownika
        entries = Archive.query.filter(
            db.func.date(Archive.date) == today,
            Archive.user_id == current_user.id  # Dodanie filtrowania po user_id
        ).all()

        if not entries:
            logging.info("No entries found for today's date.")
            return jsonify({'message': 'No data available for today'})
        
        total_call_duration = sum(entry.average_call_duration * entry.total_calls for entry in entries)

        stats = {
            'total_calls': sum(entry.total_calls for entry in entries),
            'successful_calls': sum(entry.successful_calls for entry in entries),
            'failed_calls': sum(entry.failed_calls for entry in entries),
            'cancelled_calls': sum(entry.cancelled_calls for entry in entries),
            'voicemail_calls': sum(entry.voicemail_calls for entry in entries),
            'bye_status_calls': sum(entry.bye_status_calls for entry in entries),
            'call_ended_successfully': sum(entry.call_ended_successfully for entry in entries),
            'other_errors': sum(entry.other_errors for entry in entries),
            'average_call_duration': sum(entry.average_call_duration for entry in entries) / len(entries) if entries else 0,
            'total_call_duration': total_call_duration
        }

        logging.info(f"Stats: {stats}")

        return jsonify(stats)
    
    except Exception as e:
        logging.error(f"Error in dashboard_stats: {e}")
        return jsonify({'error': 'An error occurred while fetching dashboard stats.'}), 500



@app.route('/api/calls_over_time', methods=['GET'])
@login_required
def calls_over_time():
    try:
        from datetime import datetime, timedelta

        # Pobierz dane dla ostatnich 30 dni (lub dowolnej innej liczby dni/miesięcy)
        days_ago = request.args.get('days_ago', 30, type=int)
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_ago)

        calls_over_time = db.session.query(
            db.func.date(Archive.date).label('date'),
            db.func.count(Archive.id).label('total_calls')
        ).filter(
            Archive.date >= start_date,
            Archive.date <= end_date
        ).group_by(db.func.date(Archive.date)).all()

        data = {
            'labels': [entry.date.strftime('%Y-%m-%d') for entry in calls_over_time],
            'values': [entry.total_calls for entry in calls_over_time]
        }

        return jsonify(data)

    except Exception as e:
        logging.error(f"Error in calls_over_time: {e}")
        return jsonify({'error': 'An error occurred while fetching calls over time.'}), 500

@app.route('/api/success_rate_over_time', methods=['GET'])
@login_required
def success_rate_over_time():
    try:
        from datetime import datetime, timedelta

        days_ago = request.args.get('days_ago', 30, type=int)
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_ago)

        success_rate_over_time = db.session.query(
            db.func.date(Archive.date).label('date'),
            db.func.sum(Archive.successful_calls).label('successful_calls'),
            db.func.count(Archive.id).label('total_calls')
        ).filter(
            Archive.date >= start_date,
            Archive.date <= end_date
        ).group_by(db.func.date(Archive.date)).all()

        data = {
            'labels': [entry.date.strftime('%Y-%m-%d') for entry in success_rate_over_time],
            'values': [(entry.successful_calls / entry.total_calls) * 100 if entry.total_calls > 0 else 0 for entry in success_rate_over_time]
        }

        return jsonify(data)

    except Exception as e:
        logging.error(f"Error in success_rate_over_time: {e}")
        return jsonify({'error': 'An error occurred while fetching success rate over time.'}), 500



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
