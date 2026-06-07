# Secure Node

A Flask-based security training application demonstrating role-based access control, multi-factor authentication, file integrity verification, and cryptographic operations.

## Overview

Secure Node is an educational information security lab project designed to illustrate security concepts including:

- **Multi-Factor Authentication (MFA)** with OTP verification
- **Role-Based Access Control (RBAC)** with clearance levels
- **File Integrity Verification** using SHA256 hashing
- **Data Encryption/Decryption** with Fernet symmetric cryptography
- **Audit Logging** for security event tracking
- **Virtual Vault System** with tiered access control

## Features

### Authentication & Authorization

- Email-based login with password validation
- Two-factor authentication via OTP (One-Time Password)
- Superadmin accounts receive OTPs via secure console
- Standard/Admin accounts receive OTPs via email
- Role-based access control with three clearance levels:
  - **Standard**: Basic access to portal features (Cryptography and Integrity operations)
  - **Admin**: User management and audit log access
  - **Superadmin**: Administrative user management with console-only 2FA delivery and full administrative control over Admin entities

### Security Operations

- **Encryption/Decryption**: AES encryption using Fernet
- **File Hashing**: SHA256 integrity signatures for file verification
- **Checksum Validation**: Verify file integrity using signature files
- **Audit Logging**: Comprehensive security event tracking with timestamps

### Virtual Vault

- Clearance-based file access system
- Three security levels:
  - Public (Standard clearance)
  - Internal (Admin clearance)
  - Classified (Superadmin clearance)
- Secure backend proxy for remote file access via Google Drive integration
- Access logging for all vault operations

### Admin Dashboard

- User provisioning and management
- Password and role modification
- User account deletion
- Real-time audit log viewing (last 20 events)

## Project Structure

```
secure-node/
├── app.py              # Main Flask application
├── core_logic.py       # Business logic and security functions
├── data.json.example   # Example user database template
├── data.json           # Local user database (gitignored)
├── templates/          # HTML templates for web interface
├── security.log        # Audit log file (generated at runtime)
└── README.md           # This file
```

## Installation

### Requirements

- Python 3.8+
- Flask
- requests
- cryptography
- python-dotenv

### Setup

1. Clone the repository:

```bash
git clone https://github.com/UsairamGhouri/Secure-Node.git
cd secure-node
```

2. Install dependencies:

```bash
pip install flask requests cryptography python-dotenv
```

3. Create a `.env` file in the project root (copy from `.env.example`):

```bash
cp .env.example .env
```

4. Configure environment variables in `.env`:

```
SENDER_EMAIL=your-email@gmail.com
SENDER_APP_PASSWORD=your-app-specific-password
FLASK_SECRET_KEY=your-secure-random-key-here
```

5. Create a `data.json` file in the project root (copy from `data.json.example`):

```bash
cp data.json.example data.json
```

**⚠️ Important Security Notes:**

- **Never commit `.env` or `data.json` files to version control** (both are in `.gitignore`)
- Use Gmail [App Passwords](https://support.google.com/accounts/answer/185833) instead of your main password
- Generate a strong `FLASK_SECRET_KEY` using: `python -c "import secrets; print(secrets.token_hex(32))"`
- For production, use a secrets management service instead of `.env` files

6. Run the application:

```bash
python app.py
```

The application will start on `http://127.0.0.1:5000`

## Default Credentials

The `data.json.example` template includes pre-configured test accounts using example domains:

| Email | Role | Passphrase | Purpose |
|-------|------|------------|---------|
| superadmin@example.com | Superadmin | Superadmin123! | Console-based 2FA, administrative control |
| admin@example.com | Admin | Admin123! | Email-based 2FA, Standard user modification |
| user@example.com | Standard | Standard123! | Email-based 2FA, Cryptography and Integrity operations |



*Note: Passwords are hashed in data.json. For lab purposes, password policies require:*

- *Minimum 8 characters*
- *At least one uppercase letter*
- *At least one lowercase letter*
- *At least one digit*

## Usage

### User Login Flow

1. Navigate to `/login`
2. Enter email and password
3. Receive OTP via email (or console for Superadmin)
4. Verify OTP on `/2fa` page
5. Access role-appropriate dashboard

### Portal Operations

- **Encrypt Text**: Generate encrypted payload with key and checksum
- **Decrypt Text**: Decrypt data using provided cipher and key
- **Generate File Signature**: Create SHA256 hash for file integrity
- **Verify File**: Validate file integrity against signature

### Admin Panel

- View all users and their roles
- Provision new users
- Modify existing user credentials and roles
- Delete user accounts
- Monitor audit logs

### Virtual Vault

- Access clearance-based documents
- Download files via secure backend proxy
- All access attempts logged

## Security Features

### Authentication

- Password hashing using SHA256
- OTP-based two-factor authentication
- Session management with secure tokens
- Role-based access enforcement

### Cryptography

- Fernet (symmetric encryption) for data encryption
- SHA256 for file integrity verification
- OTP generation with 6-digit codes

### Audit Trail

- Comprehensive logging of all security events
- Timestamp-based event tracking
- User and action attribution
- Event categorization (AUTH, AUTH_2FA, PROVISION, etc.)

## API Endpoints

| Route               | Method    | Description                      |
| ------------------- | --------- | -------------------------------- |
| `/`               | GET       | Home page                        |
| `/login`          | GET, POST | User authentication              |
| `/2fa`            | GET, POST | OTP verification                 |
| `/portal`         | GET, POST | Cryptography and file operations |
| `/vault`          | GET, POST | Clearance-based file access      |
| `/admin`          | GET, POST | Admin dashboard                  |
| `/edit/<email>`   | GET, POST | User modification                |
| `/delete/<email>` | GET       | User deletion                    |
| `/logout`         | GET       | Session termination              |

## Configuration

### Environment Variables

Create a `.env` file with the following variables (see `.env.example`):

```
SENDER_EMAIL=your-email@gmail.com
SENDER_APP_PASSWORD=your-app-specific-password
FLASK_SECRET_KEY=your-secure-random-key-here
```

**Security Best Practices:**

- Store `.env` files locally only - never commit to version control
- Use environment-specific secrets management in production
- Rotate credentials regularly
- Use Google App Passwords instead of your main Gmail password

### Virtual Vault

Configure in `app.py`:

- Update `VIRTUAL_VAULT` list with actual Google Drive file IDs
- Modify clearance requirements as needed

## Educational Use

This project is designed for information security education and training. It demonstrates:

- Secure authentication patterns
- Access control implementation
- Cryptographic operations
- Security logging practices
- Risk-based authorization

## License

This project is licensed under the terms provided in the [LICENSE](./LICENSE) file.

## Notes

### Security

- **Credentials Protection**: All sensitive configuration is stored in `.env` (excluded from version control)
- **Test Data**: Uses example domains (`@example.com`) instead of real email addresses
- **Secret Management**: Use environment variables, never hardcode secrets
- **Password Storage**: All passwords are hashed with SHA256 before storage
- This is an educational application and should not be used in production
- Email functionality requires valid Gmail credentials and app-specific passwords
- File uploads are limited to 16MB by default

### Before Sharing Code

- ✅ Ensure `.env` and `data.json` are in `.gitignore` (already configured)
- ✅ Never commit actual credentials, databases, or email addresses
- ✅ Replace real test data with example data
- ✅ Use `.env.example` and `data.json.example` to document required formats and variables
