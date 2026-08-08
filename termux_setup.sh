#!/data/data/com.termux/files/usr/bin/bash
set -e

# Update Termux packages
pkg update -y
pkg upgrade -y

# Install required base packages
pkg install python git -y

# Ensure pip is available and upgraded
python -m pip install --upgrade pip

# Install Python requirements from the repository
python -m pip install -r requirements.txt

echo "\nTermux setup complete. Run the scanner with:\n  python vps_hunter_v6.py -p hetzner -r de -c 1\n"