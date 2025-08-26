# Twilio SMS Pro (Users, Splits, GHL Push)

A multi-user web app for Twilio SMS: add users, split campaigns among reps, view all messages, and auto-push positive replies to GoHighLevel.

## Key Features
- **Auth & Roles**: Admin/User with login (Flask-Login, bcrypt)
- **User Management**: Admin can add users
- **Assignments**: Split a blast across selected users via **Round Robin** or **Percent Split**
- **Visibility**: Admin sees everything. Users see their assigned/outbound messages and shared inbound
- **Logs**: Per-job CSV export
- **STOP/HELP/START** handling, local suppressions
- **GHL Integration**: Positive replies POSTed to your `GHL_POSITIVE_WEBHOOK_URL` (set in Admin → Settings)

## Setup
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # fill in Twilio + admin creds
python app.py
```
Visit http://localhost:5000 → Login using `ADMIN_EMAIL`/`ADMIN_PASSWORD` from `.env`

## Running Blasts
1. Admin (or user) clicks **New Campaign**
2. Upload CSV (`phone,name,company`; remap columns if needed)
3. Choose assignment strategy and users (for splits)
4. Create → Admin can **Start** the job (users can prepare but only admin starts/pauses by default)
5. Monitor progress, download logs, view messages

## GHL Push
- Go to **Admin → Settings** and set:
  - `GHL Positive Webhook URL`
  - Optional headers JSON for auth
- When inbound text contains keywords like `yes`, `interested`, `call me`, the app will POST `{from, body, source}` to your URL.

## Deploy
Use Render/Railway/Heroku/Fly. Persist `data/` and `uploads/` if possible.
Set env: `TWILIO_*`, `FLASK_SECRET_KEY`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and optionally `PUBLIC_WEBHOOK_URL`.
