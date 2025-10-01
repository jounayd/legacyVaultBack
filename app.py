from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
from datetime import datetime, timezone
import click

app = Flask(__name__)
CORS(app)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'legacyvault.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Hostinger Email Configuration ---
SMTP_HOST = "smtp.hostinger.com"
SMTP_PORT = 465
SMTP_USER = "jy@jounayd.net"
# --- MODIFICATION START ---
# Corrected the password to remove the trailing period.
SMTP_PASS = "JOUjou84!"
# --- MODIFICATION END ---
FROM_EMAIL = "jy@jounayd.net"


# --- Database Models ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    last_login = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    vault_items = db.relationship('VaultItem', backref='owner', lazy=True, cascade="all, delete-orphan")
    beneficiaries = db.relationship('Beneficiary', backref='owner', lazy=True, cascade="all, delete-orphan")
    verifiers = db.relationship('Verifier', backref='owner', lazy=True, cascade="all, delete-orphan")
    protocol = db.relationship('Protocol', backref='owner', uselist=False, cascade="all, delete-orphan")

class VaultItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(80), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    beneficiary_email = db.Column(db.String(120), nullable=True)
    
    def to_dict(self):
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "encrypted_content": self.encrypted_content,
            "beneficiary_email": self.beneficiary_email
        }

class Beneficiary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='pending')
    is_primary = db.Column(db.Boolean, default=False, nullable=False)
    
    def to_dict(self): 
        return {
            "id": self.id, 
            "email": self.email, 
            "owner_id": self.user_id, 
            "owner_email": self.owner.email, 
            "status": self.status,
            "is_primary": self.is_primary
        }

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
    key_shards = db.relationship('KeyShard', backref='protocol', lazy=True, cascade="all, delete-orphan")
    shard_submissions = db.relationship('ShardSubmission', backref='protocol', lazy=True, cascade="all, delete-orphan")
    initiated_at = db.Column(db.DateTime, nullable=True)
    initiated_by = db.Column(db.String(120), nullable=True)


class KeyShard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    verifier_email = db.Column(db.String(120), nullable=False)
    x_coord = db.Column(db.Text, nullable=False) 
    y_coord = db.Column(db.Text, nullable=False) 
    protocol_id = db.Column(db.Integer, db.ForeignKey('protocol.id'), nullable=False)

    def to_dict(self):
        return {
            "verifier_email": self.verifier_email,
            "x": self.x_coord,
            "y": self.y_coord
        }

class ShardSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    verifier_email = db.Column(db.String(120), nullable=False)
    x_coord = db.Column(db.Text, nullable=False) 
    y_coord = db.Column(db.Text, nullable=False) 
    protocol_id = db.Column(db.Integer, db.ForeignKey('protocol.id'), nullable=False)
    def to_dict(self): return {"verifier_email": self.verifier_email, "x": self.x_coord, "y": self.y_coord}

# --- CLI and Email Functions ---

@app.cli.command("init-db")
def init_db_command():
    """Clear the existing data and create new tables."""
    db.create_all()
    click.echo("Initialized the database.")

def _send_email(to_email, subject, html_content):
    if not SMTP_PASS:
        print(f"!!! SMTP not configured. Skipping email send to {to_email}. !!!")
        return False
    
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = FROM_EMAIL
    message["To"] = to_email
    message.attach(MIMEText(html_content, "html"))
    
    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(FROM_EMAIL, to_email, message.as_string())
        print(f"Email '{subject}' sent to {to_email} via Hostinger.")
        return True
    except Exception as e:
        print(f"Error sending email via Hostinger: {e}")
        return False

def send_welcome_email(to_email):
    subject = "Welcome to LegacyVault!"
    html_content = """
    <strong>Welcome to LegacyVault!</strong>
    <p>Your secure, decentralized vault has been created.</p>
    <p><b>CRITICAL:</b> Your security is based on your Master Password. We never store it and cannot recover it for you. If you forget your password, you will lose access to your vault forever. Please store it in a safe place.</p>
    """
    _send_email(to_email, subject, html_content)

def send_designee_added_email(to_email, owner_email, role):
    subject = f"You have been designated as a {role} on LegacyVault"
    html_content = """
    <strong>Hello,</strong>
    <p>You have been designated as a {role} for {owner_email}'s LegacyVault account.</p>
    <p>Please download the LegacyVault app and create an account with this email address ({to_email}) to accept your role and view your responsibilities.</p>
    """.format(role=role, owner_email=owner_email, to_email=to_email)
    _send_email(to_email, subject, html_content)
    
def send_owner_designee_added_notification(owner_email, designee_email, role):
    subject = f"You have added a new {role}"
    html_content = """
    <strong>Hello {owner_email},</strong>
    <p>This is a confirmation that you have successfully added {designee_email} as a {role} for your LegacyVault account.</p>
    <p>They have been sent an invitation to join and accept their role.</p>
    """.format(owner_email=owner_email, designee_email=designee_email, role=role)
    _send_email(owner_email, subject, html_content)

def send_protocol_initiation_emails(owner, initiator_email):
    print(f"Sending protocol initiation alerts for owner {owner.email}...")
    
    owner_subject = "URGENT: Your LegacyVault Protocol Has Been Initiated"
    owner_html = """
    <strong>Hello {owner_email},</strong>
    <p>This is an urgent notification to inform you that the 'Fallen Star' protocol for your LegacyVault account was initiated by {initiator_email}.</p>
    <p><b>If this is a mistake, please log in to your account immediately and revert the protocol.</b></p>
    """.format(owner_email=owner.email, initiator_email=initiator_email)
    _send_email(owner.email, owner_subject, owner_html)
    
    all_designees = owner.beneficiaries + owner.verifiers
    designee_subject = f"LegacyVault Protocol Initiated for {owner.email}"
    designee_html = """
    <strong>Hello,</strong>
    <p>This is a notification that the 'Fallen Star' protocol for {owner_email}'s LegacyVault account has been initiated by {initiator_email}.</p>
    <p>If you are a verifier, you may now log in to the app to submit your approval shard. The vault cannot be unlocked until enough verifiers have approved.</p>
    """.format(owner_email=owner.email, initiator_email=initiator_email)
    for designee in all_designees:
        if designee.status == 'accepted':
            _send_email(designee.email, designee_subject, designee_html)

def send_shard_distribution_email(verifier_email, owner_email, shard_data):
    subject = f"Your LegacyVault Key Shard for {owner_email}"
    html_content = """
    <strong>Hello {verifier_email},</strong>
    <p>The owner of the LegacyVault account, {owner_email}, has secured their vault and distributed the encrypted key shards.</p>
    <p>This email contains your unique shard. <b>Please keep this email safe and do not delete it.</b> You will need the information from this shard to help unlock the vault if the protocol is ever initiated.</p>
    <hr>
    <p><b>Your Key Shard:</b></p>
    <pre>
    X-Coordinate: {x_coord}
    Y-Coordinate: {y_coord}
    </pre>
    <hr>
    <p>No action is needed from you at this time. This is for your records only.</p>
    """.format(
        verifier_email=verifier_email, 
        owner_email=owner_email, 
        x_coord=shard_data['x'], 
        y_coord=shard_data['y']
    )
    _send_email(verifier_email, subject, html_content)


# --- API Endpoints ---

@app.route("/api/register", methods=['POST'])
def register():
    data = request.get_json()
    email = data['email'].lower()
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 409
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(email=email, password_hash=hashed_password)
    new_user.protocol = Protocol(status='active')
    db.session.add(new_user)
    db.session.commit()
    send_welcome_email(new_user.email)
    return jsonify({"message": "User registered", "user_id": new_user.id}), 201

@app.route("/api/login", methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email'].lower()).first()
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({"error": "Invalid credentials"}), 401
    
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()
    
    return jsonify({"message": "Login successful", "user_id": user.id})

@app.route("/api/roles/<email>", methods=['GET'])
def get_roles_for_email(email):
    lower_email = email.lower()
    beneficiary_roles = Beneficiary.query.filter_by(email=lower_email).all()
    verifier_roles = Verifier.query.filter_by(email=lower_email).all()
    roles = {
        "beneficiary_of": [b.to_dict() for b in beneficiary_roles],
        "verifier_for": [v.to_dict() for v in verifier_roles]
    }
    return jsonify(roles)

@app.route("/api/vault/<int:user_id>", methods=['GET', 'POST'])
def manage_user_vault(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if request.method == 'GET':
        return jsonify([item.to_dict() for item in user.vault_items])
    
    if request.method == 'POST':
        data = request.get_json()
        
        if not all(k in data for k in ['category', 'title', 'encrypted_content']):
            return jsonify({"error": "Missing required fields: category, title, encrypted_content"}), 400

        new_item = VaultItem(
            category=data["category"],
            title=data["title"],
            encrypted_content=data["encrypted_content"],
            beneficiary_email=data.get("beneficiary_email"),
            user_id=user_id
        )
        db.session.add(new_item)
        db.session.commit()
        return jsonify(new_item.to_dict()), 201

@app.route("/api/vault/item/<int:item_id>", methods=['PUT', 'DELETE'])
def manage_vault_item(item_id):
    item = VaultItem.query.get(item_id)
    if not item:
        return jsonify({"error": "Item not found"}), 404
    
    if request.method == 'PUT':
        data = request.get_json()
        item.category = data.get("category", item.category)
        item.title = data.get("title", item.title)
        item.encrypted_content = data.get("encrypted_content", item.encrypted_content)
        item.beneficiary_email = data.get("beneficiary_email", item.beneficiary_email)
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
    beneficiaries = [b.to_dict() for b in user.beneficiaries]
    verifiers = [v.to_dict() for v in user.verifiers]
    return jsonify({"beneficiaries": beneficiaries, "verifiers": verifiers})

@app.route("/api/beneficiary/<int:user_id>", methods=['POST'])
def add_beneficiary(user_id):
    user = User.query.get(user_id)
    if not user: return jsonify({"error": "User not found"}), 404
    data = request.get_json()
    email = data['email'].lower()

    if Beneficiary.query.filter_by(user_id=user_id, email=email).first():
        return jsonify({"error": "Beneficiary already added"}), 409

    is_first_beneficiary = not user.beneficiaries
    
    new_beneficiary = Beneficiary(email=email, owner=user, status='pending', is_primary=is_first_beneficiary)
    db.session.add(new_beneficiary)
    db.session.commit()
    send_designee_added_email(email, user.email, 'Beneficiary')
    send_owner_designee_added_notification(user.email, email, 'Beneficiary')
    return jsonify(new_beneficiary.to_dict()), 201

@app.route("/api/beneficiary/<int:beneficiary_id>", methods=['DELETE'])
def delete_beneficiary(beneficiary_id):
    beneficiary = Beneficiary.query.get(beneficiary_id)
    if not beneficiary: return jsonify({"error": "Beneficiary not found"}), 404
    
    if beneficiary.is_primary:
        return jsonify({"error": "Cannot delete the primary beneficiary. Please set another beneficiary as primary first."}), 400
        
    db.session.delete(beneficiary)
    db.session.commit()
    return jsonify({"message": "Beneficiary deleted"})

@app.route("/api/beneficiary/set_primary/<int:beneficiary_id>", methods=['POST'])
def set_primary_beneficiary(beneficiary_id):
    new_primary = Beneficiary.query.get(beneficiary_id)
    if not new_primary: return jsonify({"error": "Beneficiary not found"}), 404

    current_primary = Beneficiary.query.filter_by(user_id=new_primary.user_id, is_primary=True).first()
    if current_primary:
        current_primary.is_primary = False
    
    new_primary.is_primary = True
    db.session.commit()
    return jsonify(new_primary.to_dict())


@app.route("/api/verifier/<int:user_id>", methods=['POST'])
def add_verifier(user_id):
    user = User.query.get(user_id)
    if not user: return jsonify({"error": "User not found"}), 404
    data = request.get_json()
    email = data['email'].lower()
    verifier_type = data.get('verifier_type', 'personal')
    if verifier_type not in ['personal', 'professional', 'notary']:
        return jsonify({"error": "Invalid verifier type"}), 400

    new_verifier = Verifier(email=email, verifier_type=verifier_type, owner=user, status='pending')
    db.session.add(new_verifier)
    db.session.commit()
    send_designee_added_email(email, user.email, 'Verifier')
    send_owner_designee_added_notification(user.email, email, 'Verifier')
    return jsonify(new_verifier.to_dict()), 201

@app.route("/api/verifier/<int:verifier_id>", methods=['PUT', 'DELETE'])
def manage_verifier(verifier_id):
    verifier = Verifier.query.get(verifier_id)
    if not verifier: return jsonify({"error": "Verifier not found"}), 404
    if request.method == 'PUT':
        data = request.get_json()
        verifier.email = data.get('email', verifier.email).lower()
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

@app.route("/api/protocol/shards/<int:user_id>", methods=['POST'])
def post_shards(user_id):
    user = User.query.get(user_id)
    if not user or not user.protocol: return jsonify({"error": "User or protocol not found"}), 404
    data = request.get_json()
    shards = data.get('shards') 
    if not isinstance(shards, list): return jsonify({"error": "Invalid payload: 'shards' must be a list"}), 400
    
    KeyShard.query.filter_by(protocol_id=user.protocol.id).delete()
    
    for shard_info in shards:
        new_shard = KeyShard(
            protocol_id=user.protocol.id,
            verifier_email=shard_info['verifier_email'].lower(),
            x_coord=shard_info['x'],
            y_coord=shard_info['y']
        )
        db.session.add(new_shard)
        send_shard_distribution_email(new_shard.verifier_email, user.email, shard_info)

    db.session.commit()
    return jsonify({"message": f"{len(shards)} shards have been stored and sent."})

@app.route("/api/protocol/shards/<int:user_id>", methods=['GET'])
def get_shards(user_id):
    user = User.query.get(user_id)
    if not user or not user.protocol:
        return jsonify({"error": "User or protocol not found"}), 404
    
    shards = KeyShard.query.filter_by(protocol_id=user.protocol.id).all()
    if not shards:
        return jsonify([])

    return jsonify([shard.to_dict() for shard in shards])


@app.route("/api/protocol/shard/<int:owner_user_id>/<path:verifier_email>", methods=['GET'])
def get_shard_for_verifier(owner_user_id, verifier_email):
    owner = User.query.get(owner_user_id)
    if not owner or not owner.protocol: return jsonify({"error": "Protocol not found"}), 404
    shard = KeyShard.query.filter_by(protocol_id=owner.protocol.id, verifier_email=verifier_email.lower()).first()
    if not shard: return jsonify({"error": "Shard not found for this verifier"}), 404
    return jsonify({"verifier_email": shard.verifier_email, "x": shard.x_coord, "y": shard.y_coord})

@app.route("/api/protocol/status/<int:owner_user_id>", methods=['GET'])
def get_protocol_status(owner_user_id):
    owner = User.query.get(owner_user_id)
    if not owner or not owner.protocol: return jsonify({"error": "Protocol not found for this user"}), 404
    
    primary_beneficiary = Beneficiary.query.filter_by(user_id=owner_user_id, is_primary=True).first()
    primary_beneficiary_email = primary_beneficiary.email if primary_beneficiary else None

    required_shards = 2 
    submitted_shards = len(owner.protocol.shard_submissions)
    
    return jsonify({
        "status": owner.protocol.status, 
        "owner_email": owner.email, 
        "required_shards": required_shards, 
        "submitted_shards": submitted_shards,
        "primary_beneficiary_email": primary_beneficiary_email,
        "initiated_at": owner.protocol.initiated_at.isoformat() if owner.protocol.initiated_at else None,
        "initiated_by": owner.protocol.initiated_by
    })

@app.route("/api/protocol/initiate/<int:owner_user_id>", methods=['POST'])
def initiate_protocol(owner_user_id):
    data = request.get_json()
    initiator_email = data.get('initiator_email')
    if not initiator_email:
        return jsonify({"error": "Initiator email is required"}), 400

    owner = User.query.get(owner_user_id)
    if not owner or not owner.protocol: return jsonify({"error": "Protocol not found"}), 404

    is_valid_verifier = Verifier.query.filter_by(user_id=owner_user_id, email=initiator_email.lower(), status='accepted').first()
    if not is_valid_verifier:
        return jsonify({"error": "Only an accepted verifier can initiate the protocol."}), 403

    accepted_verifiers_count = Verifier.query.filter_by(user_id=owner_user_id, status='accepted').count()
    if accepted_verifiers_count < 2: 
        return jsonify({"error": f"Protocol cannot be initiated. At least 2 accepted verifiers are required, but only {accepted_verifiers_count} were found."}), 400

    owner.protocol.status = "pending"
    owner.protocol.initiated_at = datetime.now(timezone.utc)
    owner.protocol.initiated_by = initiator_email.lower()
    db.session.commit()
    
    send_protocol_initiation_emails(owner, initiator_email)
    
    return jsonify({"message": "Protocol initiated. The protocol is now pending verifier approval."})


@app.route("/api/protocol/submit_shard/<int:owner_user_id>", methods=['POST'])
def submit_shard(owner_user_id):
    data = request.get_json()
    verifier_email = data.get('verifier_email', '').lower()
    x_coord = data.get('x')
    y_coord = data.get('y')
    owner = User.query.get(owner_user_id)
    if not owner or not owner.protocol: return jsonify({"error": "Protocol not found"}), 404
    if not verifier_email or not x_coord or not y_coord: return jsonify({"error": "Verifier email and shard coordinates are required"}), 400
    
    if owner.protocol.status == 'active':
        return jsonify({"error": "Protocol has not been initiated yet."}), 400
    
    existing_submission = ShardSubmission.query.filter_by(protocol_id=owner.protocol.id, verifier_email=verifier_email).first()
    if existing_submission: return jsonify({"message": "Shard already submitted"}), 200
    original_shard = KeyShard.query.filter_by(protocol_id=owner.protocol.id, verifier_email=verifier_email).first()
    if not original_shard or original_shard.x_coord != x_coord or original_shard.y_coord != y_coord: return jsonify({"error": "Invalid shard submitted."}), 400
    new_submission = ShardSubmission(protocol_id=owner.protocol.id, verifier_email=verifier_email, x_coord=x_coord, y_coord=y_coord)
    db.session.add(new_submission)
    db.session.commit()
    if len(owner.protocol.shard_submissions) >= 2:
        owner.protocol.status = "released"
        db.session.commit()
    return jsonify({"message": "Shard submitted successfully"})

@app.route("/api/protocol/submitted_shards/<int:owner_user_id>", methods=['GET'])
def get_submitted_shards(owner_user_id):
    owner = User.query.get(owner_user_id)
    if not owner or not owner.protocol: return jsonify({"error": "Protocol not found"}), 404
    if owner.protocol.status != "released": return jsonify({"error": "Protocol not yet released"}), 403
    submissions = ShardSubmission.query.filter_by(protocol_id=owner.protocol.id).all()
    return jsonify({"shards": [s.to_dict() for s in submissions]})

@app.route("/api/beneficiary/vault/<int:owner_user_id>", methods=['GET'])
def get_beneficiary_vault(owner_user_id):
    owner = User.query.get(owner_user_id)
    if not owner or not owner.protocol: 
        return jsonify({"error": "Protocol not found"}), 404

    if owner.protocol.status != "released":
        return jsonify({"error": "Access denied. Vault not yet released."}), 403

    requester_email = request.args.get('beneficiary_email')
    if not requester_email:
        return jsonify({"error": "beneficiary_email parameter is required"}), 400

    beneficiary_role = Beneficiary.query.filter_by(user_id=owner_user_id, email=requester_email.lower()).first()
    if not beneficiary_role:
        return jsonify({"error": "Access denied. You are not a designated beneficiary for this vault."}), 403
    
    if beneficiary_role.is_primary:
        items = VaultItem.query.filter(
            VaultItem.user_id == owner_user_id,
            (VaultItem.beneficiary_email == None) | (VaultItem.beneficiary_email == requester_email.lower())
        ).all()
    else:
        items = VaultItem.query.filter_by(user_id=owner_user_id, beneficiary_email=requester_email.lower()).all()

    return jsonify([item.to_dict() for item in items])
        
@app.route("/api/protocol/reset/<int:owner_user_id>", methods=['POST'])
def reset_protocol(owner_user_id):
    owner = User.query.get(owner_user_id)
    if not owner or not owner.protocol: return jsonify({"error": "Protocol not found"}), 404
    owner.protocol.status = "active"
    owner.protocol.initiated_at = None
    owner.protocol.initiated_by = None
    ShardSubmission.query.filter_by(protocol_id=owner.protocol.id).delete()
    db.session.commit()
    return jsonify({"message": "Protocol has been reset"})

@app.route("/api/health", methods=['GET'])
def health_check(): return jsonify(status="ok", message="LegacyVault Python API is running")

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=4455, debug=True)

