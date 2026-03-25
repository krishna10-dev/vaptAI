# VaptAI

VaptAI is a Vulnerability Assessment and Penetration Testing (VAPT) tool powered by AI. It features a Flask-based backend for security scanning and a React-based frontend for a modern user interface.

## Prerequisites

Before you begin, ensure you have the following installed:
- [Python 3.12+](https://www.python.org/downloads/)
- [Node.js & npm](https://nodejs.org/)
- [Git](https://git-scm.com/)

## Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/krishna10-dev/vaptAI.git
cd vaptAI
```

### 2. Backend Setup (Flask)
```bash
# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the backend server
cd backend
python app.py
```
*Note: The backend runs on `http://127.0.0.1:5000` by default.*

### 3. Frontend Setup (React + Vite)
Open a new terminal window:
```bash
cd frontend

# Install dependencies
npm install

# Start the development server
npm run dev
```
*Note: The frontend usually runs on `http://localhost:5173`.*

## Project Structure
- `backend/`: Flask server, AI helpers, and scanning logic.
- `frontend/`: React source code and UI components.
- `vapt_data.db`: SQLite database for storing scan results.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://choosealicense.com/licenses/mit/)
