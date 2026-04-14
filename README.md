# VaptAI

VaptAI is an AI-assisted Vulnerability Assessment and Penetration Testing (VAPT) toolkit with:
- A Flask backend for scanning, recon, reporting, and utility endpoints
- A React + Vite frontend dashboard
- AI-generated analysis, patch guidance, and chat assistant support

## Features

- Interactive scan orchestration (`quick` / `full`)
- Recon modules: WHOIS, DNS, SSL/TLS inspection, geo info, tech fingerprinting
- Port/service scan integration with `nmap`
- Optional deep template-based checks with `nuclei`
- AI security analysis and remediation suggestions
- AI chat assistant for findings follow-up
- PDF report generation
- Hashing, AES/Base64 utilities, and PCAP parsing support

## Tech Stack

- Backend: Python, Flask, SQLite
- Frontend: React, Vite, Axios, Recharts
- AI: Google GenAI (`google-genai`)

## Project Structure

- `backend/` Flask app, scanner/recon/AI modules, SQLite DB
- `frontend/` React app
- `requirements.txt` Python dependencies
- `SESSION_LOG.md` Notes/history

## Prerequisites

Install these first:

- Python `3.12+`
- Node.js `18+` (or newer LTS)
- npm
- Git

For full scan functionality:

- `nmap` (required for port/service vulnerability scanning)
- `nuclei` (optional, used in `full` scan mode)

## Setup

### 1. Clone

```bash
git clone https://github.com/krishna10-dev/vaptAI.git
cd vaptAI
```

### 2. Backend setup

```bash
python -m venv venv

# Linux/macOS
source venv/bin/activate

# Windows (PowerShell)
# .\venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Configure AI key

```bash
cp backend/.env.example backend/.env
```

Edit `backend/.env`:

```env
GEMINI_API_KEY=your_real_key_here
GEMINI_MODEL=gemini-2.5-flash
```

### 4. Frontend setup

```bash
cd frontend
npm install
cd ..
```

## Run Locally

Open 2 terminals.

### Terminal 1: Backend

```bash
cd backend
../venv/bin/python app.py
```

Backend runs at: `http://127.0.0.1:5000`

### Terminal 2: Frontend

```bash
cd frontend
npm run dev
```

Frontend runs at: `http://127.0.0.1:5173`

## Verify Installation

- Backend health check:

```bash
curl http://127.0.0.1:5000/api/history
```

- Frontend:
  - Open `http://127.0.0.1:5173`

## API Endpoints (Core)

- `POST /api/scan` start scan
- `GET /api/scan_status/<scan_id>` poll scan status
- `GET /api/history` recent scans
- `POST /api/ai_analyze` AI report generation
- `POST /api/chat` AI chat assistant
- `POST /api/ai_patch` AI patch suggestions
- `POST /api/report` PDF report generation

## Free Deployment (Netlify + Render)

This repo is pre-configured for:
- Frontend on Netlify (`netlify.toml`)
- Backend on Render (`render.yaml`)

### 1. Deploy Backend on Render (Free)

1. Push this repo to GitHub.
2. In Render dashboard, click `New` -> `Blueprint`.
3. Select this repository.
4. Render will detect `render.yaml` and create `vaptai-backend`.
5. In Render service environment variables, set:
   - `GEMINI_API_KEY=your_real_key`
   - Optional: `GEMINI_MODEL=gemini-2.5-flash`
6. Deploy and copy backend URL:
   - Example: `https://vaptai-backend.onrender.com`

### 2. Deploy Frontend on Netlify (Free)

1. In Netlify dashboard, click `Add new site` -> `Import an existing project`.
2. Select this repository.
3. Netlify will use `netlify.toml` automatically.
4. Add environment variable:
   - `VITE_API_BASE_URL=https://vaptai-backend.onrender.com/api`
5. Deploy site.

### 3. Verify Live App

- Open your Netlify URL.
- Run a scan and test AI chat.
- If AI fails, verify backend `GEMINI_API_KEY` and quota.

## Important Notes

- If `nmap` is missing, scan now completes with warnings (recon still works; port scan is skipped).
- AI features require a valid Gemini API key and available quota.
- Do not commit real API keys. Keep `backend/.env` private.
- Free tiers may sleep after inactivity; first request can be slow.

## Troubleshooting

- `Port 5000 already in use`:
  - Stop previous backend process and restart.
- `nmap program was not found in path`:
  - Install system `nmap` and ensure it is in `PATH`.
- AI returns offline/fallback message:
  - Verify `backend/.env` key and quota/billing status.
- Frontend cannot reach backend:
  - Ensure backend is running at `127.0.0.1:5000`.

## Security & Legal

Use this project only on systems you own or are explicitly authorized to test.

## License

MIT
