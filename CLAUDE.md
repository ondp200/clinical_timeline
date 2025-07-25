# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **Clinical Timeline App** built with Streamlit that provides secure medical data visualization and user management capabilities. The application features role-based access control, clinical timeline visualization with Plotly, and comprehensive audit logging.

## Quick Start Commands

### Environment Setup
```bash
cd clinical_timeline_app_fullcode
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Environment Configuration
Copy `.env.example` to `.env` and configure as needed:
```bash
cp .env.example .env
```

### Running the Application
```bash
streamlit run streamlit_app.py
```

Default login credentials:
- Username: **admin**
- Password: **Admin123!**

## Architecture Overview

### Single-File Application Structure
The entire application is contained in `streamlit_app.py` (~350 lines) with a monolithic architecture:

- **Authentication System**: Custom bcrypt-based login with failed attempt tracking and CAPTCHA
- **Role-Based Access Control**: Admin vs Viewer roles with different UI capabilities
- **Data Persistence**: JSON files for user data (`users.json`), failed login attempts (`failed_attempts.json`), and audit logs (`audit.log`)
- **Security Features**: Password encryption via Fernet, environment variable encryption, comprehensive audit logging
- **Clinical Visualization**: Plotly-based timeline charts showing patient stays, diagnoses, and medications

### Key Components

#### Authentication Flow (`streamlit_app.py:65-120`)
- Login/password reset tabs
- Failed attempt lockout with CAPTCHA after 3 failures
- Password complexity validation (8+ chars, upper/lower/number/special)
- Session state management for authentication

#### Admin Panel (`streamlit_app.py:262-346`)
- User role management and password resets
- Account unlocking for failed login attempts
- New user creation with email validation
- Audit log viewing and download

#### Clinical Timeline Visualization (`streamlit_app.py:126-260`)
- Hardcoded patient data visualization
- Interactive Plotly charts with admission/discharge periods
- Diagnosis and medication timeline annotations
- Date range selectors and zoom capabilities

### Security Implementation
- Fernet encryption for sensitive environment variables (prefixed with `enc::`)
- bcrypt password hashing with salt
- Comprehensive audit logging for all user actions
- Session-based authentication with role enforcement

## Data Files
- `users.json`: User credentials and roles
- `failed_attempts.json`: Login failure tracking
- `audit.log`: Security and user action audit trail
- `.env`: Environment variables (create from `.env.example`)
- `.env.key`: Fernet encryption key (if using encrypted env vars)

## Development Notes
- No test framework or linting tools configured
- Virtual environment included in repository (`venv/` directory)
- No build process - direct Python execution via Streamlit
- No external database dependencies - uses local JSON file storage

## Authentication Issues & Solutions

### Bcrypt Version Compatibility Issue
**Problem**: Authentication failed due to bcrypt version mismatch between environments:
- System Python: bcrypt 3.2.0
- Conda/Streamlit environment: bcrypt 4.3.0

**Symptoms**: 
- Hashes generated in command line failed with "Invalid salt" errors in Streamlit
- bcrypt.checkpw() returned False even for correct passwords
- Manual hash generation outside Streamlit environment didn't work

**Solution**: 
- Always generate bcrypt hashes within the same environment where they'll be verified
- Use conda environment (bcrypt 4.3.0) for any hash operations
- The working admin hash was generated directly in Streamlit runtime

### Current Working Credentials
- Username: `admin`
- Password: `Admin123!`
- Hash in users.json: Generated by Streamlit's bcrypt 4.3.0

### Authentication Flow Fix
**Original Issue**: `st.stop()` after successful login prevented main app from loading
**Solution**: Replaced `st.stop()` with `st.rerun()` to refresh page and show main application

### Environment Commands
```bash
# Use conda environment for consistency with Streamlit
conda activate base
python3 -c "import bcrypt; print('bcrypt version:', bcrypt.__version__)"  # Should show 4.3.0

# Check environment versions
python3 -c "import bcrypt; print('bcrypt version:', bcrypt.__version__)"
```

### Deployment Notes
- Ensure users.json is committed to Git for Streamlit Cloud deployment
- Streamlit Cloud uses its own Python environment - hashes must be compatible