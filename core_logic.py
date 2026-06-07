import json
import hashlib
import re
import datetime
import os
import random
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from cryptography.fernet import Fernet
from markupsafe import escape
from dotenv import load_dotenv

load_dotenv()

LOG_FILE = 'security.log'
ENCRYPTED_LOG_FILE = 'security_encrypted.log'
LOG_ENCRYPTION_KEY = Fernet.generate_key().decode() if not os.path.exists('.log_key') else open('.log_key').read().strip()

if not os.path.exists('.log_key'):
    with open('.log_key', 'w') as f:
        f.write(LOG_ENCRYPTION_KEY)

def sanitize_input(user_input):
    if not isinstance(user_input, str):
        return user_input
    return escape(str(user_input))

SENDER_EMAIL = os.getenv('SENDER_EMAIL', 'default@gmail.com')
SENDER_APP_PASSWORD = os.getenv('SENDER_APP_PASSWORD', '') 

def _send_email(target_email, subject, text, html):
    """Internal helper to send styled emails via SMTP."""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = SENDER_EMAIL
        msg['To'] = target_email
        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html, 'html'))
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True, "Email transmitted successfully."
    except Exception as e:
        return False, str(e)

def send_email_otp(target_email, otp):
    text = f"SECURE NODE ALERTS\nYour OTP is: {otp}\nDo not share this code."
    html = f"""
    <html>
      <body style="background-color: #162423; color: #9cd1d1; font-family: 'Courier New', monospace; padding: 40px; margin: 0; text-align: center;">
        <div style="background-color: #1a2b2a; padding: 30px; border: 1px solid #2a4040; border-radius: 8px; max-width: 500px; margin: 0 auto;">
          <h2 style="color: #eb8282; border-bottom: 1px dashed #2a4040; padding-bottom: 10px; margin-top: 0; letter-spacing: 2px;">SECURE NODE | 2FA</h2>
          <p style="color: #6a9c9c; font-size: 14px;">A clearance level authorization request was initiated.</p>
          <div style="background-color: #111c1b; border: 1px solid #2a4040; padding: 20px; margin: 30px 0;">
            <span style="font-size: 12px; color: #6a9c9c; display: block; margin-bottom: 10px;">ONE-TIME PASSPHRASE:</span>
            <strong style="color: #fff; font-size: 32px; letter-spacing: 8px;">{otp}</strong>
          </div>
          <p style="font-size: 12px; color: #555;">Do not share this code. If you did not request this transmission, contact your System Administrator immediately.</p>
        </div>
      </body>
    </html>
    """
    return _send_email(target_email, 'SECURE NODE | 2FA Authorization Code', text, html)

def send_welcome_email(target_email, password, role, backup_codes=None):
    backup_text = ""
    backup_html = ""
    if backup_codes:
        backup_text = "\n\nBACKUP CODES (save these securely):\n" + "\n".join(backup_codes)
        codes_html = "".join(
            f'<span style="display: inline-block; background-color: #162423; border: 1px solid #2a4040; padding: 4px 10px; margin: 3px; font-size: 13px; color: #fff; letter-spacing: 2px;">{code}</span>'
            for code in backup_codes
        )
        backup_html = f"""
              <div style="margin-top: 20px; border-top: 1px dashed #2a4040; padding-top: 15px;">
                <span style="font-size: 12px; color: #6a9c9c; display: block; margin-bottom: 10px;">EMERGENCY BACKUP CODES (One-Time Use):</span>
                <div style="text-align: center;">{codes_html}</div>
                <p style="font-size: 11px; color: #555; margin-top: 10px;">Store these in a secure location. Each code can only be used once as a 2FA alternative.</p>
              </div>
        """

    text = f"SECURE NODE ALERTS\nIdentity: {target_email}\nPassphrase: {password}\nClearance: {role}{backup_text}"
    html = f"""
    <html>
      <body style="background-color: #162423; color: #9cd1d1; font-family: 'Courier New', monospace; padding: 40px; margin: 0; text-align: center;">
        <div style="background-color: #1a2b2a; padding: 30px; border: 1px solid #2a4040; border-radius: 8px; max-width: 500px; margin: 0 auto;">
          <h2 style="color: #eb8282; border-bottom: 1px dashed #2a4040; padding-bottom: 10px; margin-top: 0; letter-spacing: 2px;">ACCESS PROVISIONED</h2>
          <p style="color: #6a9c9c; font-size: 14px;">You have been granted access to the Secure Node environment.</p>
          
          <div style="background-color: #111c1b; border: 1px solid #2a4040; padding: 20px; margin: 30px 0; text-align: left;">
            <span style="font-size: 12px; color: #6a9c9c; display: block; margin-bottom: 5px;">IDENTITY / LOGIN:</span>
            <strong style="color: #fff; font-size: 16px; display: block; margin-bottom: 20px;">{target_email}</strong>
            
            <span style="font-size: 12px; color: #6a9c9c; display: block; margin-bottom: 5px;">TEMPORARY PASSPHRASE:</span>
            <strong style="color: #fff; font-size: 16px; display: block; margin-bottom: 20px;">{password}</strong>
            
            <span style="font-size: 12px; color: #6a9c9c; display: block; margin-bottom: 5px;">CLEARANCE LEVEL:</span>
            <strong style="color: #f0c674; font-size: 16px; display: block;">{role}</strong>
            {backup_html}
          </div>
          
          <p style="font-size: 12px; color: #555;">Memorize this passphrase. Store it in a secure vault. Destroy this transmission.</p>
        </div>
      </body>
    </html>
    """
    return _send_email(target_email, 'SECURE NODE | Access Provisioned', text, html)

def send_account_modified_email(target_email, changes_description, modified_by="System Administrator"):
    """Send alert email to user when their account info has been modified."""
    text = f"SECURE NODE SECURITY ALERT\nYour account has been modified by {modified_by}.\nChanges: {changes_description}\nIf you did not authorize this, contact your administrator immediately."
    html = f"""
    <html>
      <body style="background-color: #162423; color: #9cd1d1; font-family: 'Courier New', monospace; padding: 40px; margin: 0; text-align: center;">
        <div style="background-color: #1a2b2a; padding: 30px; border: 1px solid #2a4040; border-radius: 8px; max-width: 500px; margin: 0 auto;">
          <h2 style="color: #eb8282; border-bottom: 1px dashed #2a4040; padding-bottom: 10px; margin-top: 0; letter-spacing: 2px;">ACCOUNT MODIFIED</h2>
          <p style="color: #6a9c9c; font-size: 14px;">A system administrator has modified your account credentials.</p>
          
          <div style="background-color: #111c1b; border: 1px solid #2a4040; padding: 20px; margin: 30px 0; text-align: left;">
            <span style="font-size: 12px; color: #6a9c9c; display: block; margin-bottom: 5px;">MODIFIED BY:</span>
            <strong style="color: #f0c674; font-size: 14px; display: block; margin-bottom: 20px;">{modified_by}</strong>
            
            <span style="font-size: 12px; color: #6a9c9c; display: block; margin-bottom: 5px;">CHANGES APPLIED:</span>
            <strong style="color: #fff; font-size: 14px; display: block;">{changes_description}</strong>
          </div>
          
          <p style="font-size: 12px; color: #eb8282;">If you did not authorize these changes, contact your System Administrator immediately.</p>
        </div>
      </body>
    </html>
    """
    return _send_email(target_email, 'SECURE NODE | Account Security Alert', text, html)

def send_forgot_password_otp(target_email, otp):
    text = f"SECURE NODE ALERTS\nYour Password Reset OTP is: {otp}\nDo not share this code."
    html = f"""
    <html>
      <body style="background-color: #162423; color: #9cd1d1; font-family: 'Courier New', monospace; padding: 40px; margin: 0; text-align: center;">
        <div style="background-color: #1a2b2a; padding: 30px; border: 1px solid #2a4040; border-radius: 8px; max-width: 500px; margin: 0 auto;">
          <h2 style="color: #eb8282; border-bottom: 1px dashed #2a4040; padding-bottom: 10px; margin-top: 0; letter-spacing: 2px;">PASSWORD RESET</h2>
          <p style="color: #6a9c9c; font-size: 14px;">A password reset request was initiated for your account.</p>
          <div style="background-color: #111c1b; border: 1px solid #2a4040; padding: 20px; margin: 30px 0;">
            <span style="font-size: 12px; color: #6a9c9c; display: block; margin-bottom: 10px;">PASSWORD RESET OTP:</span>
            <strong style="color: #fff; font-size: 32px; letter-spacing: 8px;">{otp}</strong>
          </div>
          <p style="font-size: 12px; color: #555;">Do not share this code. If you did not request this, contact your System Administrator immediately.</p>
        </div>
      </body>
    </html>
    """
    return _send_email(target_email, 'SECURE NODE | Password Reset Verification', text, html)

def encrypt_log_entry(log_entry):
    try:
        f = Fernet(LOG_ENCRYPTION_KEY.encode())
        encrypted = f.encrypt(log_entry.encode())
        return encrypted.decode()
    except Exception:
        return log_entry

def decrypt_log_entry(encrypted_entry):
    """Decrypt a single encrypted log entry."""
    try:
        f = Fernet(LOG_ENCRYPTION_KEY.encode())
        decrypted = f.decrypt(encrypted_entry.encode())
        return decrypted.decode()
    except Exception:
        return None

def log_security_event(email, event_type, status, details=""):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}]|{email}|{event_type}|{status}|{details}\n"
    encrypted_entry = encrypt_log_entry(log_entry)
    with open(ENCRYPTED_LOG_FILE, 'a') as file:
        file.write(encrypted_entry + "\n")
    with open(LOG_FILE, 'a') as file:
        file.write(log_entry)

def get_audit_logs(limit=20):
    if not os.path.exists(LOG_FILE): return []
    parsed_logs = []
    with open(LOG_FILE, 'r') as file:
        lines = file.readlines()
        for line in lines[-limit:]:
            parts = line.strip().split('|')
            if len(parts) == 5:
                parsed_logs.append({"time": parts[0], "email": parts[1], "event": parts[2], "status": parts[3], "details": parts[4]})
    return parsed_logs

def generate_otp(): return str(random.randint(100000, 999999))

def generate_backup_codes(count=10):
    codes = [''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8)) for _ in range(count)]
    return codes

def hash_backup_codes(codes):
    return [hashlib.sha256(code.encode()).hexdigest() for code in codes]

def verify_backup_code(email, code):
    db = load_db()
    if email not in db: return False
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    if code_hash in db[email].get('backup_codes', []) and code_hash not in db[email].get('backup_codes_used', []):
        db[email]['backup_codes_used'].append(code_hash)
        save_db(db)
        return True
    return False

def get_remaining_backup_codes(email):
    db = load_db()
    if email not in db: return 0
    total = len(db[email].get('backup_codes', []))
    used = len(db[email].get('backup_codes_used', []))
    return total - used
def hash_file(file_stream):
    sha256_hash = hashlib.sha256()
    for byte_block in iter(lambda: file_stream.read(4096), b""): sha256_hash.update(byte_block)
    file_stream.seek(0)
    return sha256_hash.hexdigest()

def verify_file_integrity(file_stream, signature_stream):
    actual_hash = hash_file(file_stream)
    try:
        sig_content = signature_stream.read().decode('utf-8').strip()
        expected_hash = sig_content.split()[0].lower()
        if len(expected_hash) != 64: return False
        return actual_hash == expected_hash
    except Exception: return False

def hash_text(text): return hashlib.sha256(text.encode()).hexdigest()

def get_rate_limit_for_role(role):
    limits = {'Standard': 30, 'Admin': 100, 'Superadmin': 500}
    return limits.get(role, 30)

def generate_key(): return Fernet.generate_key().decode()
def encrypt_payload(text, key): return Fernet(key.encode()).encrypt(text.encode()).decode()
def decrypt_payload(cipher_text, key):
    try: return Fernet(key.encode()).decrypt(cipher_text.encode()).decode()
    except Exception: return "DECRYPTION FAILED: Invalid Key or Corrupted Payload"

def load_db():
    try:
        with open('data.json', 'r') as file: return json.load(file)
    except FileNotFoundError: return {}

def save_db(db):
    with open('data.json', 'w') as file: json.dump(db, file, indent=4)

def validate_email(email): return re.match(r'^[\w\.-]+@gmail\.com$', email) is not None
def validate_password(password):
    if len(password) < 8 or not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'[0-9]', password): return False
    return True

def verify_credentials(email, password):
    db = load_db()
    if email in db:
        if db[email]['password_hash'] == hashlib.sha256(password.encode()).hexdigest():
            return db[email]['role']
    return None

def add_user(email, password, role):
    if not validate_email(email): return False, "Error: Must be @gmail.com."
    if not validate_password(password): return False, "Error: Weak Passphrase."
    db = load_db()
    if email in db: return False, "Error: Entity exists."
    backup_codes = generate_backup_codes(10)
    backup_codes_hashed = hash_backup_codes(backup_codes)
    db[email] = {
        "password_hash": hashlib.sha256(password.encode()).hexdigest(),
        "role": role,
        "backup_codes": backup_codes_hashed,
        "backup_codes_used": []
    }
    save_db(db)
    email_success, email_err = send_welcome_email(email, password, role, backup_codes=backup_codes)
    if email_success:
        return True, f"Entity '{email}' provisioned. Credentials & backup codes emailed."
    else:
        return True, f"Entity provisioned, but email failed (Check SMTP config)."

def update_user(old_email, new_email, new_password, new_role, modified_by="System Administrator"):
    if not validate_email(new_email): return False, "Error: Must be @gmail.com."
    db = load_db()
    if new_email != old_email and new_email in db: return False, "Error: Identity in use."
    
    old_role = db[old_email]['role']
    
    if new_password:
        if not validate_password(new_password): return False, "Error: Weak Passphrase."
        new_hash = hashlib.sha256(new_password.encode()).hexdigest()
    else: new_hash = db[old_email]['password_hash']
    
    existing_backup_codes = db[old_email].get('backup_codes', [])
    existing_backup_codes_used = db[old_email].get('backup_codes_used', [])
    
    del db[old_email]
    db[new_email] = {
        "password_hash": new_hash,
        "role": new_role,
        "backup_codes": existing_backup_codes,
        "backup_codes_used": existing_backup_codes_used
    }
    save_db(db)
    
    changes = []
    if new_email != old_email:
        changes.append(f"Email changed from {old_email} to {new_email}")
    if new_password:
        changes.append("Password was reset")
    if new_role != old_role:
        changes.append(f"Role changed from {old_role} to {new_role}")
    
    if changes:
        change_desc = " | ".join(changes)
        send_account_modified_email(new_email, change_desc, modified_by=modified_by)
    
    return True, "Entity modified."

def delete_user(email):
    db = load_db()
    if email in db:
        del db[email]
        save_db(db)

def get_all_users(): return load_db()
