# Android / Termux Setup for Sana

This repository includes `vps_hunter_v6.py`, a Python-based VPS scanning tool.

## Requirements
- Termux installed on Android
- Python 3.12+ available in Termux
- `pkg` package manager in Termux

## Installation Steps
1. Open Termux.
2. Update packages:
   ```bash
   pkg update && pkg upgrade -y
   ```
3. Install Python and dependencies:
   ```bash
   pkg install python git -y
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```
4. Clone the repository or copy files into Termux:
   ```bash
   git clone https://github.com/safarypouya6-dot/Sana.git
   cd Sana
   ```
5. Run the script:
   ```bash
   python vps_hunter_v6.py -p hetzner -r de -c 1
   ```

## Notes
- This tool is network-intensive and should only be used on authorized targets.
- The repository includes `requirements.txt` to install required packages.
- For Termux-specific setup, use `--setup` if you want to install optional dependencies.
