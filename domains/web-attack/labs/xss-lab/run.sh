#!/bin/bash

echo "=========================================="
echo "XSS Vulnerability Lab"
echo "=========================================="
echo ""

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
fi

echo "Installing dependencies..."
pip install -q -r requirements.txt

echo ""
echo "Starting the lab server..."
echo "Access the lab at: http://localhost:5000"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python app.py

