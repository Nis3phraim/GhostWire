#!/bin/bash
# GhostWire Lab Enviroment Setup

echo "[*] GhostWire Lab Setup"
pip install -r requirements.txt

# Create required directories if missing
mkdir -p keys data/uploads logs

# Add .gitkeep files so empty dirs track in git
touch keys/.gitkeep data/uploads/.gitkeep logs/.gitkeep

# Generate RSA key-pair
python3 generate_keys.py

echo "[+] Ready.Start the server with: python3 server/ghostwire.py
 
