from database import db  # Importuj db z nowego pliku

class Bot(db.Model):
    __tablename__ = 'bot'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    client_id = db.Column(db.String(255), nullable=False)
    secret_key = db.Column(db.String(255), nullable=False)
    settings = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    start_hour = db.Column(db.String(5), nullable=False, default='00:00')
    end_hour = db.Column(db.String(5), nullable=False, default='23:59')
    retry_time_between_calls = db.Column(db.Integer, nullable=False, default=0)
    max_retries = db.Column(db.Integer, nullable=False, default=1)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'name', name='uq_user_name'),
    )