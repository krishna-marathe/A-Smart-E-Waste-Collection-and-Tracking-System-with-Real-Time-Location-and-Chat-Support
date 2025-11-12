from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from geoalchemy2 import Geometry
from geoalchemy2.functions import ST_AsGeoJSON, ST_Point, ST_DWithin, ST_GeogFromWKB # <-- NEW IMPORT
from flask_socketio import SocketIO, join_room, leave_room, send, emit # Added SocketIO imports
from geoalchemy2 import Geography # <-- NEW IMPORT
from sqlalchemy.sql import cast # <-- NEW IMPORT
from geopy.geocoders import Nominatim
from geoalchemy2.shape import to_shape
from datetime import datetime
from functools import wraps # For decorators
from flask_cors import CORS
from sqlalchemy.orm import aliased
from flask_socketio import SocketIO
from sqlalchemy import func, cast, text
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user # --- Imports for Auth ---
from flask_bcrypt import Bcrypt # --- Imports for Auth ---
import os# --- Imports for File Uploads ---
import json # --- Imports for File Uploads ---
from werkzeug.utils import secure_filename # --- Imports for File Uploads ---
# from models import ClaimRequest

# -----------------------------------------------------
# 1. APP & DB CONFIGURATION
# -----------------------------------------------------

app = Flask(__name__)

# --- Your Keys ---

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SECRET_KEY'] = 'fa3c7494dd04b422fb6d8646900d9e17e2936cfe0d562783165fc3e2c7435fbd'

# --- File Upload Configuration ---
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16MB max file size

# Initialize extensions
db = SQLAlchemy(app)
# CORS(app) # <-- NEW LINE
socketio = SocketIO(app, cors_allowed_origins="*") # <-- UPDATED LINE
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
migrate = Migrate(app, db)

# Configure Flask-Login
login_manager.login_view = 'login' 
login_manager.login_message_category = 'info' 

# Initialize the geocoder
geolocator = Nominatim(user_agent="ewaste-app")

# -----------------------------------------------------
# 2. DATABASE MODELS (THE "ACCOUNT/PROFILE" MODEL)
# -----------------------------------------------------

# Flask-Login: This loads the *login account*
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- User Model (SIMPLIFIED) ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    profiles = db.relationship('Profile', backref='user', lazy=True, cascade="all, delete-orphan")

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# --- Profile Model (NEW) ---
class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    profile_name = db.Column(db.String(100), nullable=False) # e.g., "My Home", "My Business"
    role = db.Column(db.String(50), nullable=False) # 'disposer' or 'collector'
    full_name = db.Column(db.String(100))
    phone_number = db.Column(db.String(20))
    address = db.Column(db.String(255))
    location = db.Column(Geometry(geometry_type='POINT', srid=4326))
    current_latitude = db.Column(db.Float)
    current_longitude = db.Column(db.Float)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    requests_made = db.relationship('Request', foreign_keys='Request.disposer_profile_id', backref='disposer_profile', lazy=True)
    requests_collected = db.relationship('Request', foreign_keys='Request.collector_profile_id', backref='collector_profile', lazy=True)

# --- Request Model (UPDATED) ---
class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(50), nullable=False, default='Pending')
    submitted_on = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    disposer_profile_id = db.Column(db.Integer, db.ForeignKey('profile.id'), nullable=False)
    collector_profile_id = db.Column(db.Integer, db.ForeignKey('profile.id'), nullable=True) 
    location_access = db.Column(db.Boolean, nullable=False, default=False)  # 👈 new field
    claimed_on = db.Column(db.DateTime, nullable=True)  # <— NEW
    unclaimed_by_id = db.Column(db.Integer, db.ForeignKey('profile.id'), nullable=True)
    claim_allowed_for_id = db.Column(db.Integer, db.ForeignKey('profile.id'), nullable=True)
    approval_revoked_on = db.Column(db.DateTime, nullable=True)
    completed_on = db.Column(db.DateTime, nullable=True)
    images = db.relationship('Image', backref='request', lazy=True, cascade="all, delete-orphan")

class ClaimRequest(db.Model):
    __tablename__ = 'claim_request'

    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id', ondelete='CASCADE'))
    collector_id = db.Column(db.Integer, db.ForeignKey('profile.id', ondelete='CASCADE'))
    status = db.Column(db.String(20), default='Pending')  # Pending, Approved, Rejected
    created_on = db.Column(db.DateTime, default=datetime.utcnow)
    collector = db.relationship('Profile', backref='claim_requests', lazy=True)
    request = db.relationship('Request', backref='claim_requests_list', lazy=True)

# --- Image Model (No change needed) ---
class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)

# --- Message Model for Chat ---
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    sender_profile_id = db.Column(db.Integer, db.ForeignKey('profile.id'), nullable=False)
    receiver_profile_id = db.Column(db.Integer, db.ForeignKey('profile.id'), nullable=True)# NEW: direct recipient (lets us show messages 1:1)
    collector_profile_id = db.Column(db.Integer, db.ForeignKey('profile.id'), nullable=True)# NEW: which collector and disposer this conversation belongs to
    disposer_profile_id  = db.Column(db.Integer, db.ForeignKey('profile.id'), nullable=True)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)
    status = db.Column(db.String(20), default='sent')  # <-- NEW: sent, delivered, seen
    sender = db.relationship('Profile', foreign_keys=[sender_profile_id])
    receiver = db.relationship('Profile', foreign_keys=[receiver_profile_id], lazy='joined')
    collector = db.relationship('Profile', foreign_keys=[collector_profile_id], lazy='joined')
    disposer  = db.relationship('Profile', foreign_keys=[disposer_profile_id], lazy='joined')
    request = db.relationship('Request', foreign_keys=[request_id])

# --- NEW: Notification Model ---
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipient_profile_id = db.Column(db.Integer, db.ForeignKey('profile.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, nullable=False, default=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    link_url = db.Column(db.String(255)) 
    recipient = db.relationship('Profile', foreign_keys=[recipient_profile_id])

# -----------------------------------------------------
# 3. HELPER FUNCTIONS & DECORATORS
# -----------------------------------------------------

def get_active_profile():
    if 'active_profile_id' in session:
        return Profile.query.get(session['active_profile_id'])
    return None

def profile_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'active_profile_id' not in session:
            flash('Please select a profile to continue.', 'info')
            return redirect(url_for('select_profile'))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_active_profile():
    # This function now provides 'get_active_profile' AND 'unread_notifications'
    # to all of your templates, all the time.
    
    profile = get_active_profile()
    if profile:
        # Fetch unread notifications for the active profile
        unread_notifications = Notification.query.filter_by(
            recipient_profile_id=profile.id,
            is_read=False
        ).order_by(Notification.timestamp.desc()).all()
        
        return dict(
            get_active_profile=get_active_profile, 
            unread_notifications=unread_notifications
        )
        
    return dict(get_active_profile=get_active_profile, unread_notifications=[])

# -----------------------------------------------------
# 4. MAIN ROUTES (DASHBOARD)
# -----------------------------------------------------

# =========================
# 🔧 Helper: Apply radius filter
# =========================
def apply_radius(query, point_wkt, radius_meters):
    """
    Safely apply ST_DWithin radius filter, works with both Geometry and Geography types.
    """
    return query.filter(
        text(f"ST_DWithin(CAST(profile.location AS geography), ST_GeogFromText(:point_wkt), :radius)")
    ).params(point_wkt=point_wkt, radius=radius_meters)

@app.route("/")
@app.route("/index")
@login_required
@profile_required 
def index():
    profile = get_active_profile()

    # ---------- DISPOSER DASHBOARD ----------
    if profile.role == 'disposer':
        all_requests = (
            Request.query.filter_by(disposer_profile_id=profile.id)
            .order_by(Request.submitted_on.desc())
            .all()
        )

        # Split completed vs active (case-insensitive)
        completed_requests = [r for r in all_requests if r.status and r.status.lower() == 'completed']
        my_requests = [r for r in all_requests if not r.status or r.status.lower() != 'completed']

        print("✅ Completed Requests in DB:", [(r.id, r.item_name, r.status) for r in completed_requests])

        return render_template('index.html', active_profile=profile, my_requests=my_requests, completed_requests=completed_requests)

    # ---------- COLLECTOR DASHBOARD ----------
    elif profile.role == 'collector':
        search_query = request.args.get('search')
        radius_query = request.args.get('radius')

        # Use a single, consistent alias for the disposer profile in all queries
        Disposer = aliased(Profile)

        # Base queries
        pending_query = (
            Request.query.join(Profile, Request.disposer_profile_id == Profile.id)
            .filter(Request.status == 'Pending')
        )
        claimed_query = (
            Request.query.join(Profile, Request.disposer_profile_id == Profile.id)
            .filter(Request.collector_profile_id == profile.id)
            .filter(Request.status != 'Completed')
        )
        completed_query = (
            Request.query.join(Profile, Request.disposer_profile_id == Profile.id)
            .filter(Request.collector_profile_id == profile.id)
            .filter(Request.status == 'Completed')
        )

        print(f"📱 Request from {profile.full_name} (Role: {profile.role})")
        print(f"🔎 search_query={search_query}, radius_query={radius_query}")
        print(f"📍 Profile location={profile.location}")


        # 🔍 Search filter (applies to both)
        if search_query:
            search_term = f"%{search_query}%"
            pending_query = pending_query.filter(Request.item_name.ilike(search_term))
            claimed_query = claimed_query.filter(Request.item_name.ilike(search_term))
            completed_query = completed_query.filter(Request.item_name.ilike(search_term))


        # 📍 Radius filter (center = collector, target = disposer)
        if radius_query:
            try:
                # Safely check collector location
                if not getattr(profile, "location", None):
                    flash('⚠️ You must have an address set on your profile to filter by radius.', 'warning')
                else:
                    radius_meters = int(radius_query) * 1000
                    collector_point = to_shape(profile.location)
                    point_wkt = f"SRID=4326;POINT({collector_point.x} {collector_point.y})"

                    # ✅ Apply to all queries
                    pending_query = apply_radius(pending_query, point_wkt, radius_meters)
                    claimed_query = apply_radius(claimed_query, point_wkt, radius_meters)
                    completed_query = apply_radius(completed_query, point_wkt, radius_meters)

            except ValueError:
                flash('Invalid radius value.', 'danger')
            except Exception as e:
                flash(f'Error applying radius filter: {e}', 'danger')


        # Execute the queries
        pending_requests = pending_query.order_by(Request.submitted_on.desc()).all()
        all_claimed_requests = claimed_query.order_by(Request.submitted_on.desc()).all()
        completed_pickups = completed_query.order_by(Request.submitted_on.desc()).all()

        # ✅ Separate completed vs active claimed
        # completed_pickups = [r for r in all_claimed_requests if r.status and r.status.strip().lower() == 'completed']
        my_claimed_requests = [r for r in all_claimed_requests if not r.status or r.status.strip().lower() != 'completed']

        print("✅ Collector pending:", len(pending_requests))
        print("✅ Collector claimed:", len(my_claimed_requests))
        print("✅ Collector completed pickups:", [(r.id, r.item_name, r.status) for r in completed_pickups])


        # Render the collector dashboard
        return render_template(
            'index.html',
            active_profile=profile,
            pending_requests=pending_requests,
            my_claimed_requests=my_claimed_requests,
            completed_pickups=completed_pickups,  # ✅ NEW
            search_query=search_query,
            radius_query=radius_query
        )

    return "Error: Unknown user role."

@app.route('/mark_completed/<int:request_id>', methods=['POST'])
@login_required
@profile_required
def mark_completed(request_id):
    profile = get_active_profile()
    req = Request.query.get_or_404(request_id)

    # Prevent double marking
    if req.status == 'Completed':
        flash("This request is already marked as completed.", "info")
        return redirect(url_for('view_request', request_id=request_id))

    # Only the assigned collector can mark it completed
    if profile.role != 'collector' or req.collector_profile_id != profile.id:
        flash("Only the assigned collector can mark this request as completed.", "danger")
        return redirect(url_for('view_request', request_id=request_id))

    # Ensure request is in 'Accepted' state before marking completed
    if req.status != 'Accepted':
        flash("Only accepted requests can be marked as completed.", "warning")
        return redirect(url_for('view_request', request_id=request_id))

    #Mark as completed and record timestamp
    req.status = 'Completed'
    req.completed_on = datetime.utcnow()
    db.session.commit()

    flash("This request has been marked as completed. ✅", "success")
    return redirect(url_for('view_request', request_id=request_id))

# @app.route("/map-dashboard")
# @login_required
# @profile_required
# def map_dashboard():
#     profile = get_active_profile()
    
#     # Only collectors can see this page
#     if profile.role != 'collector':
#         flash('Only collectors can view the map dashboard.', 'danger')
#         return redirect(url_for('index'))

#     # We just need to load the page.
#     # The map itself will fetch data from a different route.
#     return render_template('map_dashboard.html', active_profile=profile)

@app.route("/api/pending-requests")
@login_required
@profile_required
def get_pending_requests_data():
    profile = get_active_profile()
    if profile.role != 'collector':
        return jsonify({"error": "Unauthorized"}), 403

    # Query the database for all pending requests that HAVE a location
    # Using ST_AsGeoJSON to convert the PostGIS 'location' point into a format (GeoJSON) that Leaflet can understand.
    requests = db.session.query(
        Request.id,
        Request.item_name,
        Profile.address,
        ST_AsGeoJSON(Profile.location) # Convert location to GeoJSON
    ).join(Profile, Request.disposer_profile_id == Profile.id)\
     .filter(Request.status == 'Pending')\
     .filter(Profile.location != None)\
     .all()

    # Format the data into a clean list
    features = []
    for req in requests:
        location_json = json.loads(req[3]) # Parse the GeoJSON string
        features.append({
            "type": "Feature",
            "geometry": location_json,
            "properties": {
                "id": req[0],
                "item_name": req[1],
                "address": req[2]
            }
        })

    # 'jsonify' converts our Python list into a proper JSON response
    return jsonify({
        "type": "FeatureCollection",
        "features": features
    })

# -----------------------------------------------------
# 5. PROFILE MANAGEMENT ROUTES
# -----------------------------------------------------

@app.route("/select-profile", methods=['GET', 'POST'])
@login_required
def select_profile():
    if request.method == 'POST':
        profile_id = request.form.get('profile_id')
        profile = Profile.query.filter_by(id=profile_id, user_id=current_user.id).first()
        if profile:
            session['active_profile_id'] = profile.id
            return redirect(url_for('index'))
        else:
            flash('Invalid profile selected.', 'danger')
            
    profiles = current_user.profiles
    return render_template('select_profile.html', profiles=profiles)

@app.route("/create-profile", methods=['GET', 'POST'])
@login_required
def create_profile():
    if request.method == 'POST':
        profile_name = request.form.get('profile_name')
        role = request.form.get('role')
        full_name = request.form.get('full_name')
        phone_number = request.form.get('phone_number')
        address = request.form.get('address')
        
        location_point = None
        if address:
            try:
                location_data = geolocator.geocode(address)
                if location_data:
                    location_point = f'POINT({location_data.longitude} {location_data.latitude})'
            except Exception as e:
                print(f"Geocoding error: {e}")

        new_profile = Profile(
            profile_name=profile_name,
            role=role,
            full_name=full_name,
            phone_number=phone_number,
            address=address,
            location=location_point,
            user_id=current_user.id
        )
        db.session.add(new_profile)
        db.session.commit()
        
        session['active_profile_id'] = new_profile.id
        flash(f'New profile "{profile_name}" created and activated!', 'success')
        return redirect(url_for('index'))

    return render_template('create_profile.html')

# -----------------------------------------------------
# 6. AUTHENTICATION ROUTES
# -----------------------------------------------------

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index')) 

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        profile_name = request.form.get('profile_name')
        role = request.form.get('role')
        full_name = request.form.get('full_name')
        phone_number = request.form.get('phone_number')
        address = request.form.get('address')
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please log in.', 'danger')
            return redirect(url_for('login'))

        new_user = User(email=email, password=password)
        db.session.add(new_user)
        try:
            db.session.commit()
        except:
            db.session.rollback()
            flash('Error creating user.', 'danger')
            return render_template('register.html')

        location_point = None
        if address:
            try:
                location_data = geolocator.geocode(address)
                if location_data:
                    location_point = f'POINT({location_data.longitude} {location_data.latitude})'
            except Exception as e:
                print(f"Geocoding error: {e}")

        new_profile = Profile(
            profile_name=profile_name,
            role=role,
            full_name=full_name,
            phone_number=phone_number,
            address=address,
            location=location_point,
            user_id=new_user.id
        )
        db.session.add(new_profile)
        db.session.commit()
        
        flash('Account and profile created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html') 

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if 'active_profile_id' in session:
            return redirect(url_for('index'))
        else:
            return redirect(url_for('select_profile')) 

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user, remember=request.form.get('remember'))
            profiles = user.profiles
            
            if len(profiles) == 0:
                flash('Welcome! Please create a profile to get started.', 'info')
                return redirect(url_for('create_profile'))
            
            if len(profiles) == 1:
                session['active_profile_id'] = profiles[0].id
                return redirect(url_for('index'))
            
            if len(profiles) > 1:
                return redirect(url_for('select_profile'))
        else:
            flash('Login failed. Check email and password.', 'danger')

    return render_template('login.html') 

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop('active_profile_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# -----------------------------------------------------
# 7. REQUEST MANAGEMENT ROUTES
# -----------------------------------------------------

@app.route("/submit-request", methods=['GET', 'POST'])
@login_required
@profile_required 
def submit_request():
    profile = get_active_profile()
    
    if profile.role != 'disposer':
        flash('Only disposer profiles can submit requests.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        item_name = request.form.get('item_name')
        description = request.form.get('description')
        files = request.files.getlist('images') 
        
        new_request = Request(
            item_name=item_name,
            description=description,
            disposer_profile_id=profile.id
        )
        db.session.add(new_request)
        db.session.commit() 

        image_filenames = []
        for file in files:
            if file and file.filename:
                filename = secure_filename(file.filename)
                unique_filename = f"{new_request.id}_{filename}"
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                
                file.save(save_path)
                image_filenames.append(unique_filename)
        
        if image_filenames:
            for fname in image_filenames:
                new_image = Image(filename=fname, request_id=new_request.id)
                db.session.add(new_image)
            db.session.commit()

        flash('Your e-waste request has been submitted!', 'success')
        return redirect(url_for('index'))

    return render_template('submit_request.html')

# -----------------------------------------------------
# LOCATION UPDATE ENDPOINT
# -----------------------------------------------------
@app.route("/update-location", methods=["POST"])
@login_required
@profile_required
def update_location():
    data = request.get_json()
    profile = get_active_profile()
    try:
        lat = data.get("latitude")
        lon = data.get("longitude")
        profile.current_latitude = lat
        profile.current_longitude = lon
        db.session.commit()
        return jsonify({"message": "Location updated"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400

@app.route("/update-disposer-location", methods=["POST"])
@login_required
@profile_required
def update_disposer_location():
    data = request.get_json()
    profile = get_active_profile()

    if profile.role != "disposer":
        return jsonify({"error": "Unauthorized"}), 403

    try:
        lat = data.get("latitude")
        lon = data.get("longitude")
        profile.current_latitude = lat
        profile.current_longitude = lon
        db.session.commit()
        return jsonify({"message": "Disposer location updated"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400


@app.route("/request/<int:request_id>")
@login_required
@profile_required
def view_request(request_id):
    active_profile = get_active_profile()
    profile = active_profile
    req = Request.query.get_or_404(request_id)
    # Load chat history correctly based on role
    if active_profile.role == 'collector':
        chat_history = Message.query.filter_by(
            request_id=request_id,
            collector_profile_id=active_profile.id
        ).order_by(Message.timestamp.asc()).all()

    elif active_profile.role == 'disposer':
        # For disposer, initially show all messages until they pick a collector
        chat_history = []
    else:
        chat_history = []


    # --- optional existing flags ---
    can_edit = False
    can_unclaim = False

    # --- Chat permission ---
    # Inside view_request route (app.py)
    claim_requests = ClaimRequest.query.filter(
        ClaimRequest.request_id == req.id,
        ClaimRequest.status.in_(["Pending", "Approved"])
    ).all()

    # claim_requests = [cr for cr in claim_requests if cr.collector_id != req.unclaimed_by_id]

    can_chat = (
        # If the request is already accepted, both disposer and collector can chat
        (req.status == 'Accepted' and active_profile.id in [req.disposer_profile_id, req.collector_profile_id])
        or
        # If it's still pending:
        (
            req.status == 'Pending' and (
                # Collectors who have requested claim can chat
                (active_profile.role == 'collector' and 
                ClaimRequest.query.filter_by(request_id=req.id, collector_id=active_profile.id).first() is not None)
                or
                # Disposer can chat with all collectors who requested
                (active_profile.role == 'disposer' and len(claim_requests) > 0)
            )
        )
    )

    # ✅ Check if the collector has already sent a claim request
    claim_request = None
    if active_profile.role == 'collector':
        claim_request = ClaimRequest.query.filter_by(
            request_id=req.id,
            collector_id=active_profile.id
        ).first()

    # --- Show map only if collector claimed this request ---
    show_map = (
        profile.role == 'collector'
        and req.status == 'Accepted'
        and req.collector_profile_id == profile.id
    )

    # --- Allow disposer to edit only if Pending & within 24 hours ---
    can_edit = (
        profile.id == req.disposer_profile_id
        and req.status == 'Pending'
        and (datetime.utcnow() - req.submitted_on).total_seconds() < 86400
    )

    # --- Allow collector to unclaim only if within 1 hour of claiming ---
    can_unclaim = False
    if hasattr(req, "claimed_on") and req.claimed_on:
        if (
            profile.role == 'collector'
            and req.collector_profile_id == profile.id
            and req.status == 'Accepted'
            and (datetime.utcnow() - req.claimed_on).total_seconds() < 3600
        ):
            can_unclaim = True

    # --- Location data for map ---
    disposer_loc, collector_loc = None, None

    # Disposer’s location
    if req.disposer_profile and req.disposer_profile.location:
        point = to_shape(req.disposer_profile.location)
        disposer_loc = {"lat": point.y, "lng": point.x}

    # Collector’s location
    if profile.location:
        point = to_shape(profile.location)
        collector_loc = {"lat": point.y, "lng": point.x}

    # ✅ Always reload all claim requests before rendering
    claim_requests = ClaimRequest.query.filter_by(request_id=req.id).all()

    # 🔄 Reset logic visibility after revocation
    if req.claim_allowed_for_id is None and req.status == 'Pending':
        # ensure all claim requests are still visible to disposer
        pass

    return render_template(
        "request_details.html",
        req=req,
        active_profile=profile,
        chat_history=chat_history,
        can_chat=can_chat,
        claim_request=claim_request,
        claim_requests=claim_requests,
        show_map=show_map,        # ✅ new variable for template
        can_edit=can_edit,        # ✅ new variable for template
        can_unclaim=can_unclaim,  # ✅ new variable for template
        disposer_loc=disposer_loc,
        collector_loc=collector_loc
    )

@app.route("/chat_history/<int:request_id>/<int:collector_id>")
@login_required
@profile_required
def chat_history(request_id, collector_id):
    """
    Returns chat history between the disposer and a specific collector
    for the given request, including message status (sent/seen).
    """
    active_profile = get_active_profile()

    # Find the request
    req = Request.query.get_or_404(request_id)
    disposer_id = req.disposer_profile_id

    # 🚫 Access control — only disposer or that collector can see the chat
    if active_profile.id not in [disposer_id, collector_id]:
        return jsonify({"error": "Access denied"}), 403

    # ✅ Fetch only messages between this disposer & collector
    messages = (
        Message.query.filter_by(request_id=request_id)
        .filter(
            db.or_(
                db.and_(
                    Message.sender_profile_id == disposer_id,
                    Message.receiver_profile_id == collector_id,
                ),
                db.and_(
                    Message.sender_profile_id == collector_id,
                    Message.receiver_profile_id == disposer_id,
                ),
            )
        )
        .order_by(Message.timestamp.asc())
        .all()
    )

    # ✅ Convert to JSON-safe structure
    data = [
        {
            "body": m.body,
            "sender_name": m.sender.profile_name,
            "sender_id": m.sender_profile_id,
            "timestamp": m.timestamp.strftime("%Y-%m-%d %H:%M"),
            "status": m.status  # 👈 Added field for persistent ✓✓
        }
        for m in messages
    ]

    print(f"📨 Sending {len(data)} messages between disposer {disposer_id} and collector {collector_id} for request {request_id}")
    return jsonify({"messages": data})

@app.route('/request_claim/<int:request_id>', methods=['POST'])
@login_required
@profile_required
def request_claim(request_id):
    profile = get_active_profile()
    req = Request.query.get_or_404(request_id)

    # 🔒 Only collectors can request
    if profile.role != 'collector':
        flash("Only collectors can request to claim.", "danger")
        return redirect(url_for('view_request', request_id=req.id))

    # 🚫 Prevent re-claiming after unclaim
    if getattr(req, "unclaimed_by_id", None) == profile.id:
        flash("❌ You have unclaimed this request earlier and cannot claim it again.", "danger")
        return redirect(url_for('view_request', request_id=req.id))

    # 🚫 Prevent duplicate active claim requests
    existing = ClaimRequest.query.filter_by(request_id=req.id, collector_id=profile.id).first()
    if existing:
        flash("You’ve already requested to claim this item.", "info")
        return redirect(url_for('view_request', request_id=req.id))

    # ✅ Normal case — create a new claim request
    claim_req = ClaimRequest(request_id=req.id, collector_id=profile.id)
    db.session.add(claim_req)
    db.session.commit()
    flash("Your claim request has been sent to the disposer.", "success")

    return redirect(url_for('view_request', request_id=req.id))

@app.route('/revoke_claim/<int:request_id>', methods=['POST'])
@login_required
@profile_required
def revoke_claim(request_id):
    active_profile = get_active_profile()
    req = Request.query.get_or_404(request_id)

    # ✅ Only disposer can revoke approval
    if active_profile.id != req.disposer_profile_id:
        flash("Only the disposer can revoke claim approval.", "danger")
        return redirect(url_for('view_request', request_id=request_id))

    # ✅ If there's an approved collector
    if req.claim_allowed_for_id:
        revoked_collector_id = req.claim_allowed_for_id

        # 🧠 Reset approval
        req.claim_allowed_for_id = None
        req.approval_revoked_on = datetime.utcnow()

        # 🧩 Ensure the revoked collector’s claim request still exists
        claim_request = ClaimRequest.query.filter_by(
            request_id=req.id,
            collector_id=revoked_collector_id
        ).first()

        # If not found, recreate it so they can still appear in the list
        if not claim_request:
            claim_request = ClaimRequest(
                request_id=req.id,
                collector_id=revoked_collector_id
            )
            db.session.add(claim_request)

        # ✅ Optional: notify the revoked collector
        chat_notification = Notification(
            recipient_profile_id=revoked_collector_id,
            message=f"Your approval for '{req.item_name}' has been revoked by the disposer.",
            link_url=url_for('view_request', request_id=req.id)
        )
        db.session.add(chat_notification)

        db.session.commit()

        flash("✅ Approval revoked successfully. Other collectors can now be approved.", "info")
        print(f"Approval revoked for collector ID {revoked_collector_id} on request {request_id}")
    else:
        flash("No approved collector to revoke.", "info")

    return redirect(url_for('view_request', request_id=request_id))


@app.route('/claim_requests')
@login_required
@profile_required
def claim_requests():
    profile = get_active_profile()

    if profile.role != 'disposer':
        abort(403)

    pending_claims = (
        ClaimRequest.query
        .join(Request)
        .filter(Request.disposer_profile_id == profile.id, ClaimRequest.status == 'Pending')
        .all()
    )

    return render_template('claim_requests.html', claims=pending_claims)

@app.route('/approve_claim/<int:request_id>/<int:collector_id>', methods=['POST'])
@login_required
@profile_required
def approve_claim(request_id, collector_id):
    profile = get_active_profile()
    req = Request.query.get_or_404(request_id)

    # Only disposer can approve
    if profile.role != 'disposer' or req.disposer_profile_id != profile.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('view_request', request_id=req.id))

    # Find the collector’s claim request
    claim = ClaimRequest.query.filter_by(request_id=req.id, collector_id=collector_id).first()
    if not claim:
        flash("Claim request not found.", "danger")
        return redirect(url_for('view_request', request_id=req.id))

    # Mark this collector as approved
    req.claim_allowed_for_id = collector_id
    req.collector_profile_id = collector_id
    req.status = 'Pending'  # remains pending until actually claimed

    # Optionally, update all ClaimRequest entries to indicate which one was approved
    all_claims = ClaimRequest.query.filter_by(request_id=req.id).all()
    for cr in all_claims:
        cr.status = 'Approved' if cr.collector_id == collector_id else 'Rejected'

    db.session.commit()

    flash("✅ Collector has been approved for this item.", "success")
    return redirect(url_for('view_request', request_id=req.id))

@app.route("/claim/<int:request_id>", methods=['POST'])
@login_required
@profile_required
def claim_request(request_id):
    profile = get_active_profile()
    req = Request.query.get_or_404(request_id)

    if profile.role != 'collector':
        flash("Only collectors can claim requests.", "danger")
        return redirect(url_for('index'))

    # Check disposer approval
    if req.claim_allowed_for_id != profile.id:
        flash("You’re not approved by the disposer to claim this request.", "warning")
        return redirect(url_for('view_request', request_id=req.id))

    # Proceed with claim
    req.collector_profile_id = profile.id
    req.status = 'Accepted'
    req.claimed_on = datetime.utcnow()

    # Auto-mark claim request as approved
    claim_req = ClaimRequest.query.filter_by(request_id=req.id, collector_id=profile.id).first()
    if claim_req:
        claim_req.status = 'Approved'

    db.session.commit()

    flash("You have successfully claimed this item!", "success")
    return redirect(url_for('view_request', request_id=req.id))



@app.route("/edit/<int:request_id>", methods=['GET', 'POST'])
@login_required
@profile_required
def edit_request(request_id):
    req = Request.query.get_or_404(request_id)
    profile = get_active_profile()

    # must be owner of the request
    if req.disposer_profile_id != profile.id:
        flash("You can only edit your own requests.", "danger")
        return redirect(url_for('index'))

    # only while Pending and within 24 hours
    within_24h = (datetime.utcnow() - req.submitted_on).total_seconds() < 86400
    if req.status != "Pending" or not within_24h:
        flash("Editing period expired (24 hours) or request already claimed.", "warning")
        return redirect(url_for('view_request', request_id=req.id))

    if request.method == 'POST':
        req.item_name = request.form.get('item_name')
        req.description = request.form.get('description')
        # (optional) handle replacing images here if you want
        db.session.commit()
        flash("Request updated successfully!", "success")
        return redirect(url_for('view_request', request_id=req.id))

    return render_template('edit_request.html', req=req, active_profile=profile)


    # --- NEW: CREATE NOTIFICATION ---
    # Create a notification for the disposer
    new_notification = Notification(
        recipient_profile_id=req.disposer_profile_id,
        message=f"Your request for '{req.item_name}' has been claimed by {profile.profile_name}!",
        link_url=url_for('view_request', request_id=req.id)
    )
    db.session.add(new_notification)
    # --- END OF NEW CODE ---
    db.session.commit()# Commit both the request update and the new notification
    
    flash('You have successfully claimed this request!', 'success')
    return redirect(url_for('index'))

@app.route("/unclaim/<int:request_id>", methods=['POST'])
@login_required
@profile_required
def unclaim_request(request_id):
    profile = get_active_profile()
    req = Request.query.get_or_404(request_id)

    # Ensure it's the same collector who claimed it
    if profile.role != 'collector' or req.collector_profile_id != profile.id:
        flash("You can only unclaim your own accepted requests.", "danger")
        return redirect(url_for('index'))

    # Must be accepted and within 1 hour of claim
    if req.status != 'Accepted' or not req.claimed_on:
        flash("This request is not in a state you can unclaim.", "warning")
        return redirect(url_for('view_request', request_id=req.id))

    if (datetime.utcnow() - req.claimed_on).total_seconds() > 3600:
        flash("Unclaim window has expired (1 hour).", "warning")
        return redirect(url_for('view_request', request_id=req.id))

    # ✅ Mark as unclaimed
    req.unclaimed_by_id = profile.id        # remember who unclaimed
    req.collector_profile_id = None
    req.status = 'Pending'
    req.claim_allowed_for_id = None  # ✅ reset approval access
    req.claimed_on = None
    db.session.commit()

    flash("You have unclaimed this request. You won’t be able to claim it again.", "info")
    return redirect(url_for('index'))

@app.route("/toggle-location-access/<int:request_id>", methods=["POST"])
@login_required
@profile_required
def toggle_location_access(request_id):
    profile = get_active_profile()
    req = Request.query.get_or_404(request_id)

    # Only disposer of this request can toggle
    if profile.id != req.disposer_profile_id:
        flash("You can only manage location access for your own requests.", "danger")
        return redirect(url_for("view_request", request_id=request_id))

    req.location_access = not req.location_access
    db.session.commit()

    if req.location_access:
        flash("You are now sharing your live location with the collector.", "success")
    else:
        flash("You have stopped sharing your live location.", "info")

    return redirect(url_for("view_request", request_id=request_id))

@app.route("/get-disposer-location/<int:request_id>")
@login_required
@profile_required
def get_disposer_location(request_id):
    req = Request.query.get_or_404(request_id)
    profile = get_active_profile()

    # Only collector of this request can view live location
    if (
        profile.role != "collector"
        or req.collector_profile_id != profile.id
        or req.status != "Accepted"
        or not req.location_access
    ):
        return jsonify({"error": "Unauthorized or access not granted"}), 403

    disposer = req.disposer_profile
    if not disposer.current_latitude or not disposer.current_longitude:
        return jsonify({"lat": None, "lng": None})

    return jsonify({
        "lat": disposer.current_latitude,
        "lng": disposer.current_longitude
    })


@app.route("/notifications/mark-as-read", methods=['POST'])
@login_required
@profile_required
def mark_notifications_as_read():
    profile = get_active_profile()
    try:
        # Find all unread notifications for this user and set them to 'read'
        Notification.query.filter_by(
            recipient_profile_id=profile.id,
            is_read=False
        ).update({"is_read": True})
        
        db.session.commit()
        return jsonify({"success": True}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error marking notifications as read: {e}")
        return jsonify({"success": False}), 500

# -----------------------------------------------------
# 8. SOCKETIO CHAT EVENTS
# -----------------------------------------------------

# -----------------------------------------------------
# TYPING + MESSAGE STATUS EVENTS
# -----------------------------------------------------

@socketio.on('typing')
def handle_typing(data):
    """Notify other user that someone is typing."""
    room = data.get('room')
    sender_name = data.get('sender_name')
    emit('display_typing', {'sender_name': sender_name}, to=room, include_self=False)


@socketio.on('mark_seen')
def handle_mark_seen(data):
    """Mark messages as seen between disposer and collector for a specific request."""
    room = data.get('room')
    profile_id = int(data.get('profile_id'))

    try:
        # Extract IDs safely
        request_id, collector_id, disposer_id = map(int, room.split('_'))

        print(f"👁️ Marking messages as seen | Request: {request_id} | Viewer: {profile_id}")

        # Only mark messages sent *to* this viewer as seen
        messages = Message.query.filter_by(request_id=request_id).filter(
            Message.receiver_profile_id == profile_id,
            Message.status != 'seen'
        ).all()

        for msg in messages:
            msg.status = 'seen'

        db.session.commit()
        print(f"✅ {len(messages)} messages marked as seen in room {room}")

        # Notify both users
        emit('messages_seen', {'room': room}, to=room)

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error in mark_seen: {e}")

@socketio.on('join_room')
def handle_join_room(data):
    room = data['room']
    join_room(room)
    print(f"User has joined room: {room}")

@socketio.on('leave_room')
def handle_leave_room(data):
    room = data['room']
    leave_room(room)
    print(f"User has left room: {room}")

@socketio.on('send_message')
def handle_send_message(data):
    print("\n--- 'send_message' EVENT RECEIVED ---")
    print(f"Incoming Data: {data}")

    room = data.get('room')
    message_body = data.get('message', '').strip()
    sender_id = data.get('profile_id')

    if not room or not message_body or not sender_id:
        print("❌ Missing essential message data.")
        return

    # 🧠 Extract request_id, collector_id, disposer_id
    try:
        parts = room.split('_')
        request_id, collector_id, disposer_id = map(int, parts[:3])
    except Exception as e:
        print(f"❌ Invalid room format ({room}): {e}")
        return

    profile = Profile.query.get(int(sender_id))
    if not profile:
        print(f"❌ Invalid profile ID: {sender_id}")
        return

    print(f"💬 Message from: {profile.profile_name} (ID: {profile.id})")

    # Determine receiver (the opposite of sender)
    receiver_id = disposer_id if int(sender_id) == collector_id else collector_id

    try:
        print("💾 Attempting to save message...")

        # 🧱 Save message to database (robust against autoflush)
        with db.session.no_autoflush:
            new_message = Message(
                body=message_body,
                sender_profile_id=int(sender_id),
                receiver_profile_id=receiver_id,
                collector_profile_id=collector_id,
                disposer_profile_id=disposer_id,
                request_id=request_id,
                timestamp=datetime.utcnow(),
                status='sent'
            )
            db.session.add(new_message)

            # ✅ Optional: Add a notification for the receiver
            req = Request.query.get(request_id)
            if req:
                notif_text = f"New message from {profile.profile_name} about '{req.item_name}'."
                chat_notification = Notification(
                    recipient_profile_id=receiver_id,
                    message=notif_text,
                    link_url=url_for('view_request', request_id=req.id)
                )
                db.session.add(chat_notification)

            db.session.commit()

        print("✅ Message and notification saved successfully.")

        # ✅ Prepare and emit message to both users in the same room
        message_data = {
            'message': message_body,
            'sender_name': profile.profile_name,
            'sender_id': profile.id,
            'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M')
        }

        emit('chat_message', message_data, to=room)
        print(f"📤 Emitted message to room: {room}")

    except Exception as e:
        db.session.rollback()
        print(f"\n--- ❌ ERROR IN handle_send_message ---\n{e}\n-----------------------------------")

# -----------------------------------------------------
# 9. MAIN - RUN THE APP
# -----------------------------------------------------

if __name__ == '__main__':
    # IMPORTANT: If you need to add/change a table, you must temporarily 
    # add db.drop_all() back for one run.
    
    # Creates tables if they don't exist, without deleting data
    with app.app_context():
        db.create_all() 
    
    socketio.run(app, debug=True)
