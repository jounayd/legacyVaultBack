from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- Initialize the Flask App & Database ---
app = Flask(__name__)
CORS(app)

# --- Database Configuration (for SQLite) ---
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'legacyvault.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Mailtrap Configuration ---
MAILTRAP_HOST = "sandbox.smtp.mailtrap.io"
MAILTRAP_PORT = 2525
MAILTRAP_USER = os.environ.get('MAILTRAP_USER', 'bae4d3123ce126')
MAILTRAP_PASS = os.environ.get('MAILTRAP_PASS', '832f5968bcfcf0')
FROM_EMAIL = 'LegacyVault Demo <demo@legacyvault.com>'


# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    vault_items = db.relationship('VaultItem', backref='owner', lazy=True, cascade="all, delete-orphan")
    beneficiary = db.relationship('Beneficiary', backref='owner', uselist=False, cascade="all, delete-orphan")
    verifiers = db.relationship('Verifier', backref='owner', lazy=True, cascade="all, delete-orphan")
    protocol = db.relationship('Protocol', backref='owner', uselist=False, cascade="all, delete-orphan")

class VaultItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(80), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    def to_dict(self): return {"id": self.id, "category": self.category, "title": self.title, "encrypted_content": self.encrypted_content}

class Beneficiary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    status = db.Column(db.String(50), nullable=False, default='pending')
    def to_dict(self): return {"id": self.id, "email": self.email, "owner_id": self.user_id, "owner_email": self.owner.email, "status": self.status}

class Verifier(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    verifier_type = db.Column(db.String(50), nullable=False, default='personal')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='pending')
    def to_dict(self): return {"id": self.id, "email": self.email, "verifier_type": self.verifier_type, "owner_id": self.user_id, "owner_email": self.owner.email, "status": self.status}

class Protocol(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(50), nullable=False, default='active')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    shard_submissions = db.relationship('ShardSubmission', backref='protocol', lazy=True, cascade="all, delete-orphan")

class ShardSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    verifier_email = db.Column(db.String(120), nullable=False)
    protocol_id = db.Column(db.Integer, db.ForeignKey('protocol.id'), nullable=False)


# --- Helper Functions to Send Email ---
def send_invitation_email(to_email, role):
    if not MAILTRAP_USER or 'YOUR_MAILTRAP_USERNAME' in MAILTRAP_USER:
        print("!!! Mailtrap not configured. Skipping email send. !!!")
        return False
    message = MIMEMultipart("alternative")
    message["Subject"] = "You have been invited to LegacyVault"
    message["From"] = FROM_EMAIL
    message["To"] = to_email
    html_content = f'<strong>Hello,</strong><p>You have been designated as a {role} in a LegacyVault account. Please download the app and create an account with this email address to accept your role.</p>'
    message.attach(MIMEText(html_content, "html"))
    try:
        with smtplib.SMTP(MAILTRAP_HOST, MAILTRAP_PORT) as server:
            server.starttls()
            server.login(MAILTRAP_USER, MAILTRAP_PASS)
            server.sendmail(FROM_EMAIL, to_email, message.as_string())
        print(f"Email captured by Mailtrap for recipient: {to_email}")
        return True
    except Exception as e:
        print(f"Error sending email to Mailtrap: {e}")
        return False

# NEW: Email function to alert the owner
def send_protocol_alert_email(to_email):
    if not MAILTRAP_USER or 'YOUR_MAILTRAP_USERNAME' in MAILTRAP_USER:
        print("!!! Mailtrap not configured. Skipping email send. !!!")
        return False
    message = MIMEMultipart("alternative")
    message["Subject"] = "URGENT: Your LegacyVault Protocol Has Been Initiated"
    message["From"] = FROM_EMAIL
    message["To"] = to_email
    html_content = f'<strong>Hello,</strong><p>This is an urgent notification to inform you that the Fallen Star protocol for your LegacyVault account has been initiated by one of your designees.</p><p>If this is a mistake, please log in to your account immediately and revert the protocol.</p>'
    message.attach(MIMEText(html_content, "html"))
    try:
        with smtplib.SMTP(MAILTRAP_HOST, MAILTRAP_PORT) as server:
            server.starttls()
            server.login(MAILTRAP_USER, MAILTRAP_PASS)
            server.sendmail(FROM_EMAIL, to_email, message.as_string())
        print(f"Protocol alert email captured by Mailtrap for recipient: {to_email}")
        return True
    except Exception as e:
        print(f"Error sending protocol alert email: {e}")
        return False

# --- API Endpoints ---
@app.route("/api/register", methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(email=data['email']).first(): return jsonify({"error": "Email already registered"}), 409
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(email=data['email'], password_hash=hashed_password)
    new_user.protocol = Protocol(status='active')
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered", "user_id": new_user.id}), 201

@app.route("/api/login", methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if not user or not check_password_hash(user.password_hash, data['password']): return jsonify({"error": "Invalid credentials"}), 401
    return jsonify({"message": "Login successful", "user_id": user.id})

@app.route("/api/roles/<email>", methods=['GET'])
def get_roles_for_email(email):
    beneficiary_roles = Beneficiary.query.filter_by(email=email).all()
    verifier_roles = Verifier.query.filter_by(email=email).all()
    roles = { "beneficiary_of": [b.to_dict() for b in beneficiary_roles], "verifier_for": [v.to_dict() for v in verifier_roles] }
    return jsonify(roles)

@app.route("/api/vault/<int:user_id>", methods=['GET', 'POST'])
def manage_user_vault(user_id):
    user = User.query.get(user_id)
    if not user: return jsonify({"error": "User not found"}), 404
    if request.method == 'GET':
        return jsonify([item.to_dict() for item in user.vault_items])
    if request.method == 'POST':
        data = request.get_json()
        new_item = VaultItem(category=data.get("category"), title=data["title"], encrypted_content=data["encrypted_content"], user_id=user_id)
        db.session.add(new_item)
        db.session.commit()
        return jsonify(new_item.to_dict()), 201

@app.route("/api/vault/item/<int:item_id>", methods=['PUT', 'DELETE'])
def manage_vault_item(item_id):
    item = VaultItem.query.get(item_id)
    if not item: return jsonify({"error": "Item not found"}), 404
    if request.method == 'PUT':
        data = request.get_json()
        item.category = data.get("category", item.category)
        item.title = data.get("title", item.title)
        item.encrypted_content = data.get("encrypted_content", item.encrypted_content)
        db.session.commit()
        return jsonify(item.to_dict())
    elif request.method == 'DELETE':
        db.session.delete(item)
        db.session.commit()
        return jsonify({"message": "Item deleted"})

@app.route("/api/designees/<int:user_id>", methods=['GET'])
def get_designees(user_id):
    user = User.query.get(user_id)
    if not user: return jsonify({"error": "User not found"}), 404
    beneficiary = user.beneficiary.to_dict() if user.beneficiary else None
    verifiers = [v.to_dict() for v in user.verifiers]
    return jsonify({"beneficiary": beneficiary, "verifiers": verifiers})

@app.route("/api/beneficiary/<int:user_id>", methods=['POST'])
def add_or_update_beneficiary(user_id):
    user = User.query.get(user_id)
    if not user: return jsonify({"error": "User not found"}), 404
    data = request.get_json()
    if not user.beneficiary:
        new_beneficiary = Beneficiary(email=data['email'], owner=user, status='pending')
        db.session.add(new_beneficiary)
    else:
        user.beneficiary.email = data['email']
        user.beneficiary.status = 'pending'
    db.session.commit()
    send_invitation_email(data['email'], 'Primary Beneficiary')
    return jsonify(user.beneficiary.to_dict())

@app.route("/api/verifier/<int:user_id>", methods=['POST'])
def add_verifier(user_id):
    user = User.query.get(user_id)
    if not user: return jsonify({"error": "User not found"}), 404
    data = request.get_json()
    new_verifier = Verifier(email=data['email'], verifier_type=data.get('verifier_type', 'personal'), owner=user, status='pending')
    db.session.add(new_verifier)
    db.session.commit()
    send_invitation_email(data['email'], 'Verifier')
    return jsonify(new_verifier.to_dict()), 201

@app.route("/api/verifier/<int:verifier_id>", methods=['PUT', 'DELETE'])
def manage_verifier(verifier_id):
    verifier = Verifier.query.get(verifier_id)
    if not verifier: return jsonify({"error": "Verifier not found"}), 404
    if request.method == 'PUT':
        data = request.get_json()
        verifier.email = data.get('email', verifier.email)
        verifier.verifier_type = data.get('verifier_type', verifier.verifier_type)
        db.session.commit()
        return jsonify(verifier.to_dict())
    elif request.method == 'DELETE':
        db.session.delete(verifier)
        db.session.commit()
        return jsonify({"message": "Verifier deleted"})

@app.route("/api/beneficiary/accept/<int:beneficiary_id>", methods=['POST'])
def accept_beneficiary(beneficiary_id):
    beneficiary = Beneficiary.query.get(beneficiary_id)
    if not beneficiary: return jsonify({"error": "Beneficiary role not found"}), 404
    beneficiary.status = 'accepted'
    db.session.commit()
    return jsonify(beneficiary.to_dict())

@app.route("/api/verifier/accept/<int:verifier_id>", methods=['POST'])
def accept_verifier(verifier_id):
    verifier = Verifier.query.get(verifier_id)
    if not verifier: return jsonify({"error": "Verifier role not found"}), 404
    verifier.status = 'accepted'
    db.session.commit()
    return jsonify(verifier.to_dict())

# --- Fallen Star Protocol Endpoints ---
@app.route("/api/protocol/status/<int:owner_user_id>", methods=['GET'])
def get_protocol_status(owner_user_id):
    owner = User.query.get(owner_user_id)
    if not owner or not owner.protocol: return jsonify({"error": "Protocol not found for this user"}), 404
    required_shards = 2
    submitted_shards = len(owner.protocol.shard_submissions)
    return jsonify({"status": owner.protocol.status, "owner_email": owner.email, "required_shards": required_shards, "submitted_shards": submitted_shards})

@app.route("/api/protocol/initiate/<int:owner_user_id>", methods=['POST'])
def initiate_protocol(owner_user_id):
    owner = User.query.get(owner_user_id)
    if not owner or not owner.protocol: return jsonify({"error": "Protocol not found"}), 404

    # NEW: Check for minimum number of accepted verifiers
    accepted_verifiers_count = Verifier.query.filter_by(user_id=owner_user_id, status='accepted').count()
    if accepted_verifiers_count < 2:
        return jsonify({"error": f"Protocol cannot be initiated. At least 2 accepted verifiers are required, but only {accepted_verifiers_count} were found."}), 400

    owner.protocol.status = "pending"
    db.session.commit()
    # NEW: Send an alert email to the vault owner
    send_protocol_alert_email(owner.email)
    return jsonify({"message": "Protocol initiated"})

@app.route("/api/protocol/submit_shard/<int:owner_user_id>", methods=['POST'])
def submit_shard(owner_user_id):
    data = request.get_json()
    verifier_email = data.get('verifier_email')
    owner = User.query.get(owner_user_id)
    if not owner or not owner.protocol: return jsonify({"error": "Protocol not found"}), 404
    
    existing_submission = ShardSubmission.query.filter_by(protocol_id=owner.protocol.id, verifier_email=verifier_email).first()
    if existing_submission: return jsonify({"message": "Shard already submitted"}), 200
    
    new_submission = ShardSubmission(protocol_id=owner.protocol.id, verifier_email=verifier_email)
    db.session.add(new_submission)
    db.session.commit()

    submission_count = len(owner.protocol.shard_submissions)
    required_shards = 2
    
    if submission_count >= required_shards:
        owner.protocol.status = "released"
        db.session.commit()
        
    return jsonify({"message": "Shard submitted successfully"})

@app.route("/api/beneficiary/vault/<int:owner_user_id>", methods=['GET'])
def get_beneficiary_vault(owner_user_id):
    owner = User.query.get(owner_user_id)
    if not owner or not owner.protocol: return jsonify({"error": "Protocol not found"}), 404
    if owner.protocol.status == "released":
        return jsonify([item.to_dict() for item in owner.vault_items])
    else:
        return jsonify({"error": "Access denied. Vault not yet released."}), 403
        
@app.route("/api/protocol/reset/<int:owner_user_id>", methods=['POST'])
def reset_protocol(owner_user_id):
    owner = User.query.get(owner_user_id)
    if not owner or not owner.protocol: return jsonify({"error": "Protocol not found"}), 404
    owner.protocol.status = "active"
    ShardSubmission.query.filter_by(protocol_id=owner.protocol.id).delete()
    db.session.commit()
    return jsonify({"message": "Protocol has been reset"})

# --- Health Check and Main Runner ---
@app.route("/api/health", methods=['GET'])
def health_check(): return jsonify(status="ok", message="LegacyVault Python API is running")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=4455, debug=True)
    ###########