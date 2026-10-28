# DocuTrack — Student Document Expiry & Renewal Reminder System

**Domain:** Education / Productivity  **Difficulty:** Very Easy

Students keep many documents that expire: ID cards, certificates, licences, permits.
DocuTrack records them in one place, tracks expiry dates and shows renewal reminders on the dashboard.

## Features
- User registration and login (password stored as a SHA-256 hash)
- Add a document with name, type, expiry date and reminder window (7/15/30/60 days)
- Dashboard with counters: Expired, Due soon, Active, Renewed
- Reminder banner listing documents that need attention
- Documents sorted by expiry date, with status filters
- Mark as renewed (new expiry date + renewal history), delete documents
- Light and dark mode, responsive layout

## Tech stack
HTML5, CSS3, vanilla JavaScript. Data is stored in the browser's `localStorage`. No backend or build step.

## Project structure
```
docutrack/
├── index.html
├── css/style.css
├── js/app.js
├── .vscode/
├── .gitignore
├── LICENSE
└── README.md
```

## Run locally
1. Open the folder in VS Code.
2. Install the recommended extension **Live Server**.
3. Right-click `index.html` → **Open with Live Server**.

(You can also just double-click `index.html`.)

## How it works
- **Status logic:** `expired` if days left < 0; `due soon` if days left ≤ the document's reminder window; otherwise `active`.
- **Renewal:** the new expiry date must be later than the current one; each renewal is logged.

## Limitations and future work
- Data is per browser and device; login is a demo, not real security.
- Optional next steps: Node.js + Express + MongoDB backend, JWT auth, email reminders (Nodemailer) or SMS (Twilio) via a daily cron job, file upload for document scans.

## Test checklist
- [ ] Register, log out, log in again
- [ ] Wrong password shows an error
- [ ] Add documents with past, near and far dates and check badges
- [ ] Mark one renewed and see it move to Active
- [ ] Filters and delete work; data survives a page refresh

## License
MIT
