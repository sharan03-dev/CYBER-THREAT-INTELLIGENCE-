#!/bin/bash
# Start the Kavach CTI website:  ./run.sh   then open http://127.0.0.1:8000
cd "$(dirname "$0")"
[ -d .venv ] && source .venv/bin/activate
brew services list 2>/dev/null | grep -q "mongodb-community.*started" || brew services start mongodb-community@8.0
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port "${PORT:-8000}" --reload
