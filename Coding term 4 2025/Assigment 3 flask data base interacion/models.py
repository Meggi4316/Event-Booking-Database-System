# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "User"
    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    name = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=False, unique=True)
    password = db.Column(db.Text, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)

    # password reset (stored as text for portability in SQLite)
    resetToken = db.Column(db.Text)        # nullable
    resetExpires = db.Column(db.Text)      # ISO string, nullable

    tickets = db.relationship("Ticket", back_populates="user", cascade="all, delete-orphan")

class Event(db.Model):
    __tablename__ = "Event"
    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    name = db.Column(db.Text, nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=False)
    datetime = db.Column(db.DateTime, nullable=False)
    venue = db.Column(db.Text, nullable=False)

    tickets = db.relationship("Ticket", back_populates="event", cascade="all, delete-orphan")

    @property
    def booked_total(self) -> int:
        total = db.session.execute(
            db.select(db.func.coalesce(db.func.sum(Ticket.qty), 0)).where(Ticket.eventID == self.id)
        ).scalar_one()
        return int(total or 0)

    @property
    def spots_left(self) -> int:
        return max(0, self.capacity - self.booked_total)

class Ticket(db.Model):
    __tablename__ = "Ticket"
    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)

    userID = db.Column(db.BigInteger, db.ForeignKey("User.id", ondelete="CASCADE"), nullable=False)
    eventID = db.Column(db.BigInteger, db.ForeignKey("Event.id", ondelete="CASCADE"), nullable=False)

    purchaseDate = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    qty = db.Column(db.Integer, nullable=False, default=1)

    checked_in = db.Column(db.Boolean, nullable=False, default=False)
    checkinCode = db.Column(db.Text, unique=True)  # may be NULL for older rows

    user = db.relationship("User", back_populates="tickets")
    event = db.relationship("Event", back_populates="tickets")
