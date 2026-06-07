from flask import Flask, render_template, request, redirect, url_for, session, Response, stream_with_context, send_from_directory
import requests
import core_logic
import os
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev-key-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
csrf = CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
limiter.init_app(app)

def authenticated_rate_limit_key():
    user_id = session.get('email', get_remote_address())
    return user_id 

VIRTUAL_VAULT = [
    {"id": 1, "name": "Lab_Manifest.txt", "clearance": "Standard", "desc": "Public class requirements.", "gdrive_id": "1F9QR0pEGYJCcmLvwtWwqZr-UWkvbSSvh"},
    {"id": 2, "name": "Network_Topology.pdf", "clearance": "Admin", "desc": "Internal server routing infrastructure.", "gdrive_id": "1vqTfHiqA9nvBI3tnp6MGfQXFgx1_ypid"},
    {"id": 3, "name": "Master_RSA_Keys.dat", "clearance": "Superadmin", "desc": "Top secret root cryptographic keys.", "gdrive_id": "1qGLv4PKZETFTtfvbEJB8W5CPFaxp6lCV"}
]

@app.route('/')
def index(): return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.svg', mimetype='image/svg+xml')

@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' https://fonts.googleapis.com; img-src 'self' data:"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    error = None
    if request.method == 'POST':
        email = core_logic.sanitize_input(request.form['email'])
        password = request.form['password']
        role = core_logic.verify_credentials(email, password)
        if role:
            otp = core_logic.generate_otp()
            session['pending_email'] = email
            session['pending_role'] = role
            session['pending_otp'] = otp
            if role == 'Superadmin':
                session['delivery_method'] = "SECURE CONSOLE TERMINAL"
                print(f"\n{'='*40}\n[ROOT SECURITY ALERT] 2FA OTP for {email}: {otp}\n{'='*40}\n")
                core_logic.log_security_event(email, "AUTH_PHASE_1", "SUCCESS", "OTP routed to Root Console.")
            else:
                session['delivery_method'] = "REGISTERED EMAIL ADDRESS"
                success, msg = core_logic.send_email_otp(email, otp)
                if success: core_logic.log_security_event(email, "AUTH_PHASE_1", "SUCCESS", "OTP dispatched via SMTP.")
                else:
                    print(f"\n[SMTP FAILED - FALLBACK] OTP for {email}: {otp}\n")
                    core_logic.log_security_event(email, "SMTP_ERROR", "WARNING", f"Email failed: {msg}")
            return redirect(url_for('verify_2fa'))
        else:
            core_logic.log_security_event(email, "AUTH", "FAILED", "Invalid Credentials")
            error = "Authentication Failed: Invalid Credentials"
    return render_template('login.html', error=error)

@app.route('/2fa', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def verify_2fa():
    if 'pending_email' not in session: return redirect(url_for('login'))
    error = None
    delivery_method = session.get('delivery_method', 'Secure Channel')
    if request.method == 'POST':
        auth_method = request.form.get('auth_method', 'otp')
        if auth_method == 'backup':
            backup_code = request.form.get('backup_code', '')
            if core_logic.verify_backup_code(session['pending_email'], backup_code):
                session['email'] = session['pending_email']
                session['role'] = session['pending_role']
                core_logic.log_security_event(session['email'], "AUTH_2FA", "SUCCESS", "Session Established (Backup Code)")
                session.pop('pending_email', None); session.pop('pending_role', None); session.pop('pending_otp', None)
                if session['role'] in ['Admin', 'Superadmin']: return redirect(url_for('admin'))
                return redirect(url_for('portal'))
            else:
                error = "INVALID BACKUP CODE. Access Denied."
                core_logic.log_security_event(session['pending_email'], "AUTH_2FA", "FAILED", "Invalid Backup Code")
        else:
            if request.form.get('otp') == session.get('pending_otp'):
                session['email'] = session['pending_email']
                session['role'] = session['pending_role']
                core_logic.log_security_event(session['email'], "AUTH_2FA", "SUCCESS", "Session Established")
                session.pop('pending_email', None); session.pop('pending_role', None); session.pop('pending_otp', None)
                if session['role'] in ['Admin', 'Superadmin']: return redirect(url_for('admin'))
                return redirect(url_for('portal'))
            else:
                error = "INVALID OTP. Access Denied."
                core_logic.log_security_event(session['pending_email'], "AUTH_2FA", "FAILED", "Incorrect OTP")
    return render_template('2fa.html', error=error, delivery_method=delivery_method)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if session.get('role') not in ['Admin', 'Superadmin']: return redirect(url_for('portal'))
    msg = msg_color = None
    if request.method == 'POST':
        new_email = core_logic.sanitize_input(request.form['new_email'])
        new_password = request.form['new_password']
        new_role = core_logic.sanitize_input(request.form['new_role'])
        success, response_msg = core_logic.add_user(new_email, new_password, new_role)
        if success: core_logic.log_security_event(session['email'], "PROVISION", "SUCCESS", f"Created: {request.form['new_email']}")
        msg, msg_color = response_msg, ("#9cd1d1" if success else "#eb8282")
    return render_template('admin.html', users=core_logic.get_all_users(), logs=core_logic.get_audit_logs(), msg=msg, msg_color=msg_color)

@app.route('/edit/<target>', methods=['GET', 'POST'])
def edit(target):
    if session.get('role') not in ['Admin', 'Superadmin']: return redirect(url_for('portal'))
    db = core_logic.get_all_users()
    if target not in db: return redirect(url_for('admin'))
    if session['role'] == 'Admin' and db[target]['role'] in ['Admin', 'Superadmin']: return redirect(url_for('admin'))
    if db[target]['role'] == 'Superadmin' and target != session['email']: return redirect(url_for('admin'))
    msg = msg_color = None
    if request.method == 'POST':
        edit_email = core_logic.sanitize_input(request.form['edit_email'])
        edit_password = request.form['edit_password']
        edit_role = core_logic.sanitize_input(request.form['edit_role'])
        success, response_msg = core_logic.update_user(target, edit_email, edit_password, edit_role, modified_by=session.get('email', 'Unknown'))
        if success:
            core_logic.log_security_event(session['email'], "MODIFY", "SUCCESS", f"Updated: {target}")
            return redirect(url_for('admin'))
        msg, msg_color = response_msg, "#eb8282"
    return render_template('edit.html', email=target, data=db[target], msg=msg, msg_color=msg_color)

@app.route('/delete/<target>')
def delete(target):
    if session.get('role') not in ['Admin', 'Superadmin']: return redirect(url_for('portal'))
    db = core_logic.get_all_users()
    if target not in db or target == session['email'] or db[target]['role'] == 'Superadmin': return redirect(url_for('admin'))
    if session['role'] == 'Admin' and db[target]['role'] == 'Admin': return redirect(url_for('admin'))
    core_logic.delete_user(target)
    core_logic.log_security_event(session['email'], "DROP", "SUCCESS", f"Terminated: {target}")
    return redirect(url_for('admin'))

@app.route('/portal', methods=['GET', 'POST'])
@limiter.limit("100 per minute")
def portal():
    if 'email' not in session: return redirect(url_for('login'))
    enc_data = dec_data = file_verify = None
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'encrypt':
            pt = core_logic.sanitize_input(request.form['message'])
            key = core_logic.generate_key()
            enc_data = {'cipher': core_logic.encrypt_payload(pt, key), 'checksum': core_logic.hash_text(pt), 'key': key}
        elif action == 'decrypt':
            dec_data = core_logic.decrypt_payload(request.form['cipher_text'], request.form['aes_key'])
        elif action == 'hash_file':
            f = request.files['file_input']
            if f:
                h = core_logic.hash_file(f)
                core_logic.log_security_event(session['email'], "INTEGRITY", "INFO", f"Generated signature for {f.filename}")
                sig_content = f"{h}  {f.filename}"
                return Response(sig_content, mimetype="text/plain", headers={"Content-disposition": f"attachment; filename={f.filename}.sha256"})
        elif action == 'verify_file':
            f = request.files['verify_file_input']
            sig_file = request.files['signature_file']
            if f and sig_file:
                if core_logic.verify_file_integrity(f, sig_file):
                    file_verify = {"status": "SUCCESS: INTEGRITY VERIFIED", "color": "#9cd1d1"}
                    core_logic.log_security_event(session['email'], "INTEGRITY", "SUCCESS", f"Hash match for {f.filename}")
                else:
                    file_verify = {"status": "CRITICAL: INTEGRITY COMPROMISED", "color": "#eb8282"}
                    core_logic.log_security_event(session['email'], "INTEGRITY", "FAILED", f"Hash mismatch for {f.filename}")
    return render_template('portal.html', role=session['role'], email=session['email'], enc_data=enc_data, dec_data=dec_data, file_verify=file_verify)

@app.route('/vault', methods=['GET', 'POST'])
@limiter.limit("50 per minute")
def vault():
    if 'email' not in session: return redirect(url_for('login'))
    access_msg = access_color = None
    hierarchy = {"Standard": 1, "Admin": 2, "Superadmin": 3}
    user_level = hierarchy.get(session['role'], 0)
    
    if request.method == 'POST':
        req_clearance = request.form['clearance']
        file_name = request.form['file_name']
        req_level = hierarchy.get(req_clearance, 99)
        
        if user_level >= req_level:
            file_record = next((item for item in VIRTUAL_VAULT if item['name'] == file_name), None)
            
            if file_record and file_record.get('gdrive_id'):
                gdrive_id = file_record['gdrive_id']
                download_url = f"https://drive.google.com/uc?export=download&id={gdrive_id}"
                
                try:
                    r = requests.get(download_url, stream=True)
                    core_logic.log_security_event(session['email'], "FILE_ACCESS", "SUCCESS", f"Securely tunneled {file_name}")
                    
                    return Response(
                        stream_with_context(r.iter_content(chunk_size=8192)),
                        content_type=r.headers.get('content-type', 'application/octet-stream'),
                        headers={"Content-Disposition": f"attachment; filename={file_name}"}
                    )
                except Exception as e:
                    access_msg = "CRITICAL: Secure tunnel to remote vault failed."
                    access_color = "#eb8282"
                    core_logic.log_security_event(session['email'], "FILE_ACCESS", "FAILED", "Remote tunnel error")
        else:
            access_msg = f"ACCESS DENIED: Clearance ({session['role']}) insufficient."
            access_color = "#eb8282"
            core_logic.log_security_event(session['email'], "FILE_ACCESS", "FAILED", f"Denied access to {file_name}")
            
    return render_template('vault.html', vault=VIRTUAL_VAULT, role=session['role'], email=session['email'], msg=access_msg, msg_color=access_color)

@app.route('/logout')
def logout():
    if 'email' in session: core_logic.log_security_event(session['email'], "SESSION", "TERMINATED", "User Disconnected")
    session.clear()
    return redirect(url_for('index'))

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy-policy.html')

@app.route('/terms-of-service')
def terms_of_service():
    return render_template('terms-of-service.html')

@app.route('/security-disclosure')
def security_disclosure():
    return render_template('security-disclosure.html')

if __name__ == '__main__': app.run(host='127.0.0.1', port=5000, debug=True)
