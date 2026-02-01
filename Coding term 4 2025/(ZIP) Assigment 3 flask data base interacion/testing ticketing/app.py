# app.py
import os, io, csv, secrets, sqlite3
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from models import db, User, Event, Ticket

ALLOWED_CSV = {"csv"}

def _auto_migrate_sqlite(db_path: str):
    """
    Bring an existing DB up to the fields this app expects.
    Safe to run repeatedly.
    - Ticket: qty (INT, default 1), checked_in (INT, default 0), checkinCode (TEXT)
    - User: resetToken (TEXT), resetExpires (TEXT iso)
    - Useful indexes
    """
    # If DB doesn't exist yet, create_all will handle it later
    if not os.path.exists(db_path):
        return

    con = sqlite3.connect(db_path)
    con.execute("PRAGMA foreign_keys = ON;")
    cur = con.cursor()

    # Ticket columns
    cur.execute("PRAGMA table_info('Ticket');")
    t_cols = {row[1] for row in cur.fetchall()}
    if "qty" not in t_cols:
        cur.execute('ALTER TABLE "Ticket" ADD COLUMN qty INTEGER NOT NULL DEFAULT 1;')
    if "checked_in" not in t_cols:
        cur.execute('ALTER TABLE "Ticket" ADD COLUMN checked_in INTEGER NOT NULL DEFAULT 0;')
    if "checkinCode" not in t_cols:
        cur.execute('ALTER TABLE "Ticket" ADD COLUMN checkinCode TEXT;')

    # User columns for password reset
    cur.execute('PRAGMA table_info("User");')
    u_cols = {row[1] for row in cur.fetchall()}
    if "resetToken" not in u_cols:
        cur.execute('ALTER TABLE "User" ADD COLUMN resetToken TEXT;')
    if "resetExpires" not in u_cols:
        cur.execute('ALTER TABLE "User" ADD COLUMN resetExpires TEXT;')  # store ISO text

    # Indexes
    cur.execute('CREATE UNIQUE INDEX IF NOT EXISTS uq_user_email ON "User"(email);')
    cur.execute('CREATE UNIQUE INDEX IF NOT EXISTS uq_ticket_user_event ON "Ticket"(userID, eventID);')
    cur.execute('CREATE UNIQUE INDEX IF NOT EXISTS uq_ticket_checkin_code ON "Ticket"(checkinCode);')
    cur.execute('CREATE INDEX IF NOT EXISTS ix_ticket_event ON "Ticket"(eventID);')
    cur.execute('CREATE INDEX IF NOT EXISTS ix_ticket_user ON "Ticket"(userID);')
    cur.execute('CREATE INDEX IF NOT EXISTS ix_event_datetime ON "Event"(datetime);')

    con.commit()
    con.close()


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-change-me")

    # Use instance/ticketing.db (matches your logs)
    os.makedirs(app.instance_path, exist_ok=True)
    db_path = os.path.join(app.instance_path, "ticketing.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path.replace("\\", "/")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB uploads

    # Auto-migrate before ORM runs
    _auto_migrate_sqlite(db_path)

    db.init_app(app)
    with app.app_context():
        db.create_all()

    # -------- helpers --------
    def current_user():
        uid = session.get("user_id")
        return db.session.get(User, uid) if uid else None

    def login_required(fn):
        from functools import wraps
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user():
                flash("Please log in first.", "warning")
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return wrapper

    def admin_required(fn):
        from functools import wraps
        @wraps(fn)
        def wrapper(*args, **kwargs):
            u = current_user()
            if not u or not u.admin:
                return render_template("403.html"), 403
            return fn(*args, **kwargs)
        return wrapper

    # -------- public --------
    @app.route("/")
    def index():
        q = request.args.get("q", "").strip().lower()
        qry = Event.query
        if q:
            like = f"%{q}%"
            qry = qry.filter(
                db.or_(
                    db.func.lower(Event.name).like(like),
                    db.func.lower(Event.venue).like(like),
                    db.func.lower(Event.description).like(like),
                )
            )
        events = qry.order_by(Event.datetime.asc()).all()
        return render_template("index.html", events=events, q=q, user=current_user())

    @app.route("/event/<int:event_id>")
    def event_detail(event_id):
        event = db.session.get(Event, event_id)
        if not event:
            return render_template("404.html"), 404
        return render_template("event_detail.html", event=event, user=current_user())

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            if not name or not email or not password:
                flash("All fields are required.", "warning")
                return redirect(url_for("register"))

            if User.query.filter_by(email=email).first():
                flash("Email already registered. Please log in.", "warning")
                return redirect(url_for("login"))

            hashed = generate_password_hash(password)
            user = User(name=name, email=email, password=hashed, admin=False)
            db.session.add(user)
            db.session.commit()

            session["user_id"] = user.id
            return redirect(url_for("index"))
        return render_template("register.html", user=current_user())

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            user = User.query.filter_by(email=email).first()
            if not user or not check_password_hash(user.password, password):
                flash("Invalid email or password.", "danger")
                return redirect(url_for("login"))

            session["user_id"] = user.id
            return redirect(url_for("index"))
        return render_template("login.html", user=current_user())

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    # --- forgot / reset password (token-based, no email needed) ---
    @app.route("/forgot", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            user = User.query.filter_by(email=email).first()
            # Always show success to avoid leaking which emails exist
            reset_link = None
            if user:
                token = secrets.token_urlsafe(24)
                user.resetToken = token
                user.resetExpires = (datetime.utcnow() + timedelta(minutes=30)).isoformat()
                db.session.commit()
                # For demo: we show the link on the confirmation page (since emailing is out of scope)
                reset_link = url_for("reset_password", token=token, _external=False)
            return render_template("forgot_password.html", sent=True, reset_link=reset_link, user=current_user())
        return render_template("forgot_password.html", sent=False, user=current_user())

    @app.route("/reset/<token>", methods=["GET", "POST"])
    def reset_password(token):
        user = User.query.filter_by(resetToken=token).first()
        if not user:
            flash("Invalid or expired reset link.", "danger")
            return redirect(url_for("login"))
        # check expiry
        try:
            exp = datetime.fromisoformat(user.resetExpires) if user.resetExpires else None
        except Exception:
            exp = None
        if not exp or exp < datetime.utcnow():
            # Expired or missing
            user.resetToken = None
            user.resetExpires = None
            db.session.commit()
            flash("Reset link expired. Please request a new one.", "warning")
            return redirect(url_for("forgot_password"))

        if request.method == "POST":
            p1 = request.form.get("password", "")
            p2 = request.form.get("confirm", "")
            if not p1 or p1 != p2:
                flash("Passwords do not match.", "danger")
                return redirect(url_for("reset_password", token=token))
            user.password = generate_password_hash(p1)
            user.resetToken = None
            user.resetExpires = None
            db.session.commit()
            flash("Password has been reset. Please log in.", "success")
            return redirect(url_for("login"))

        return render_template("reset_password.html", token=token, user=current_user())

    # --------- booking ---------
    @app.route("/book/<int:event_id>", methods=["POST"])
    @login_required
    def book(event_id):
        event = db.session.get(Event, event_id)
        if not event:
            return render_template("404.html"), 404

        try:
            qty = int(request.form.get("qty", "1"))
        except ValueError:
            qty = 1
        qty = max(1, min(6, qty))  # group booking 1–6

        if qty > event.spots_left:
            flash(f"Only {event.spots_left} spots left.", "warning")
            return redirect(url_for("event_detail", event_id=event.id))

        u = current_user()
        if Ticket.query.filter_by(userID=u.id, eventID=event.id).first():
            flash("You already booked this event.", "info")
            return redirect(url_for("my_tickets"))

        code = secrets.token_urlsafe(6)
        t = Ticket(userID=u.id, eventID=event.id, qty=qty, checkinCode=code, checked_in=False)
        db.session.add(t)
        db.session.commit()

        flash("Ticket booked.", "success")
        return redirect(url_for("my_tickets"))

    @app.route("/my_tickets")
    @login_required
    def my_tickets():
        u = current_user()
        rows = (
            db.session.query(Ticket, Event)
            .join(Event, Ticket.eventID == Event.id)
            .filter(Ticket.userID == u.id)
            .order_by(Event.datetime.asc())
            .all()
        )
        return render_template("my_tickets.html", rows=rows, user=u)

    @app.route("/ticket/<int:ticket_id>")
    @login_required
    def ticket_view(ticket_id):
        t = db.session.get(Ticket, ticket_id)
        if not t or t.userID != session.get("user_id"):
            return render_template("403.html"), 403
        e = db.session.get(Event, t.eventID)
        u = db.session.get(User, t.userID)
        return render_template("ticket.html", t=t, e=e, the_user=u, user=current_user())

    @app.route("/cancel/<int:ticket_id>", methods=["POST"])
    @login_required
    def cancel_ticket(ticket_id):
        t = db.session.get(Ticket, ticket_id)
        if not t or t.userID != session.get("user_id"):
            return render_template("403.html"), 403
        event = db.session.get(Event, t.eventID)
        if event and event.datetime <= datetime.utcnow():
            flash("Cannot cancel after event start.", "warning")
            return redirect(url_for("my_tickets"))
        db.session.delete(t)
        db.session.commit()
        flash("Booking cancelled.", "success")
        return redirect(url_for("my_tickets"))

    # --------- admin: dashboard ---------
    @app.route("/admin")
    @admin_required
    def admin_home():
        events = Event.query.order_by(Event.datetime.asc()).all()
        total_users = db.session.execute(db.select(db.func.count(User.id))).scalar_one()
        total_events = db.session.execute(db.select(db.func.count(Event.id))).scalar_one()
        total_tickets = db.session.execute(db.select(db.func.count(Ticket.id))).scalar_one()

        occupancy = []
        for e in events:
            booked = e.booked_total
            percent = int(round((booked / e.capacity) * 100)) if e.capacity else 0
            occupancy.append((e, booked, percent))

        return render_template(
            "admin.html",
            events=events,
            stats=dict(users=total_users, events=total_events, tickets=total_tickets),
            occupancy=occupancy,
            user=current_user()
        )

    # --------- admin: users ---------
    @app.route("/admin/users")
    @admin_required
    def admin_users():
        q = request.args.get("q", "").strip().lower()
        qry = User.query
        if q:
            like = f"%{q}%"
            qry = qry.filter(
                db.or_(
                    db.func.lower(User.name).like(like),
                    db.func.lower(User.email).like(like)
                )
            )
        users = qry.order_by(User.name.asc()).all()
        return render_template("admin_users.html", users=users, q=q, user=current_user())

    @app.route("/admin/user/<int:user_id>/toggle_admin", methods=["POST"])
    @admin_required
    def admin_toggle_admin(user_id):
        u = db.session.get(User, user_id)
        if not u:
            return render_template("404.html"), 404
        # prevent locking yourself out by removing your own admin if you're the only admin
        if u.id == session.get("user_id"):
            only_admin = db.session.execute(db.select(db.func.count(User.id)).filter(User.admin == True)).scalar_one() == 1
            if only_admin and u.admin:
                flash("You are the only admin. Create another admin first.", "warning")
                return redirect(url_for("admin_users"))
        u.admin = not u.admin
        db.session.commit()
        flash(f"Admin flag set to {u.admin} for {u.email}.", "success")
        return redirect(url_for("admin_users"))

    # --------- admin: create / edit / delete event ---------
    @app.route("/admin/event/new", methods=["GET", "POST"])
    @admin_required
    def admin_event_new():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            venue = request.form.get("venue", "").strip()
            capacity = request.form.get("capacity", "0").strip()
            description = request.form.get("description", "").strip()
            dt_str = request.form.get("datetime", "").strip()

            if not name or not venue or not description or not dt_str:
                flash("All fields are required.", "warning")
                return redirect(url_for("admin_event_new"))

            try:
                capacity = int(capacity)
                when = datetime.fromisoformat(dt_str)
            except Exception:
                flash("Invalid capacity or date/time.", "danger")
                return redirect(url_for("admin_event_new"))

            e = Event(name=name, venue=venue, capacity=capacity, description=description, datetime=when)
            db.session.add(e)
            db.session.commit()
            flash("Event created.", "success")
            return redirect(url_for("admin_home"))

        return render_template("admin_event_form.html", mode="new", event=None, user=current_user())

    @app.route("/admin/event/<int:event_id>/edit", methods=["GET", "POST"])
    @admin_required
    def admin_event_edit(event_id):
        e = db.session.get(Event, event_id)
        if not e:
            return render_template("404.html"), 404

        if request.method == "POST":
            name = request.form.get("name", "").strip()
            venue = request.form.get("venue", "").strip()
            capacity = request.form.get("capacity", "0").strip()
            description = request.form.get("description", "").strip()
            dt_str = request.form.get("datetime", "").strip()

            if not name or not venue or not description or not dt_str:
                flash("All fields are required.", "warning")
                return redirect(url_for("admin_event_edit", event_id=e.id))

            try:
                capacity = int(capacity)
                when = datetime.fromisoformat(dt_str)
            except Exception:
                flash("Invalid capacity or date/time.", "danger")
                return redirect(url_for("admin_event_edit", event_id=e.id))

            if capacity < e.booked_total:
                flash(f"Capacity cannot be lower than current bookings ({e.booked_total}).", "warning")
                return redirect(url_for("admin_event_edit", event_id=e.id))

            e.name = name
            e.venue = venue
            e.capacity = capacity
            e.description = description
            e.datetime = when
            db.session.commit()
            flash("Event updated.", "success")
            return redirect(url_for("admin_event", event_id=e.id))

        iso_dt = e.datetime.strftime("%Y-%m-%dT%H:%M")
        return render_template("admin_event_form.html", mode="edit", event=e, iso_dt=iso_dt, user=current_user())

    @app.route("/admin/event/<int:event_id>/delete", methods=["POST"])
    @admin_required
    def admin_event_delete(event_id):
        e = db.session.get(Event, event_id)
        if not e:
            return render_template("404.html"), 404
        if e.tickets:
            flash("Cannot delete: event already has tickets.", "warning")
            return redirect(url_for("admin_event", event_id=e.id))
        db.session.delete(e)
        db.session.commit()
        flash("Event deleted.", "success")
        return redirect(url_for("admin_home"))

    @app.route("/admin/event/<int:event_id>")
    @admin_required
    def admin_event(event_id):
        e = db.session.get(Event, event_id)
        if not e:
            return render_template("404.html"), 404

        q = request.args.get("q", "").strip().lower()
        base = db.session.query(Ticket, User).join(User, Ticket.userID == User.id).filter(Ticket.eventID == e.id)
        if q:
            base = base.filter(
                db.or_(
                    db.func.lower(User.name).contains(q),
                    db.func.lower(User.email).contains(q),
                    db.cast(Ticket.id, db.String).contains(q),
                    db.func.lower(Ticket.checkinCode).contains(q),
                )
            )
        attendees = base.order_by(Ticket.purchaseDate.asc()).all()
        return render_template("admin_event.html", event=e, attendees=attendees, user=current_user(), query=q)

    @app.route("/admin/ticket/<int:ticket_id>/toggle_checkin", methods=["POST"])
    @admin_required
    def admin_toggle_checkin(ticket_id):
        t = db.session.get(Ticket, ticket_id)
        if not t:
            return render_template("404.html"), 404
        t.checked_in = not t.checked_in
        db.session.commit()
        flash(("Checked in" if t.checked_in else "Unchecked") + f" ticket #{t.id}.", "success")
        return redirect(url_for("admin_event", event_id=t.eventID))

    @app.route("/admin/event/<int:event_id>/export.csv")
    @admin_required
    def admin_export(event_id):
        event = db.session.get(Event, event_id)
        if not event:
            return render_template("404.html"), 404
        rows = (
            db.session.query(Ticket, User)
            .join(User, Ticket.userID == User.id)
            .filter(Ticket.eventID == event.id)
            .order_by(Ticket.purchaseDate.asc())
            .all()
        )
        sio = io.StringIO()
        w = csv.writer(sio)
        w.writerow(["TicketID", "Name", "Email", "Qty", "CheckedIn", "CheckinCode", "PurchaseDate"])
        for t, u in rows:
            w.writerow([t.id, u.name, u.email, t.qty, int(t.checked_in), t.checkinCode, t.purchaseDate])
        data = sio.getvalue().encode("utf-8")
        return send_file(io.BytesIO(data), mimetype="text/csv", as_attachment=True,
                         download_name=f"event_{event.id}_attendees.csv")

    @app.route("/admin/import", methods=["GET", "POST"])
    @admin_required
    def admin_import():
        if request.method == "POST":
            file = request.files.get("file")
            if not file or file.filename == "":
                flash("Select a CSV file.", "warning")
                return redirect(url_for("admin_import"))

            filename = secure_filename(file.filename)
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext not in ALLOWED_CSV:
                flash("Only .csv files are allowed.", "danger")
                return redirect(url_for("admin_import"))

            try:
                stream = io.StringIO(file.stream.read().decode("utf-8"))
                reader = csv.DictReader(stream)
                created = 0
                for row in reader:
                    name = (row.get("name") or "").strip()
                    venue = (row.get("venue") or "").strip()
                    description = (row.get("description") or "").strip()
                    cap_str = (row.get("capacity") or "").strip()
                    dt_str = (row.get("datetime") or "").strip()

                    if not name or not venue or not description or not cap_str or not dt_str:
                        continue

                    try:
                        capacity = int(cap_str)
                        when = datetime.fromisoformat(dt_str.replace(" ", "T"))
                    except Exception:
                        continue

                    e = Event(name=name, venue=venue, capacity=capacity, description=description, datetime=when)
                    db.session.add(e)
                    created += 1

                db.session.commit()
                flash(f"Imported {created} events.", "success")
                return redirect(url_for("admin_home"))
            except Exception:
                db.session.rollback()
                flash("Import failed. Check your CSV headers and date/time format.", "danger")
                return redirect(url_for("admin_import"))

        return render_template("admin_import.html", user=current_user())

    # -------- errors --------
    @app.errorhandler(404)
    def not_found(e):
        return render_template("404.html"), 404

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("403.html"), 403

    @app.errorhandler(500)
    def server_error(e):
        return render_template("500.html"), 500

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
