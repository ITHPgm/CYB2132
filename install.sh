#!/bin/bash
echo "Installing Website Malware Scanner..."

# Update package list
sudo apt update

# Install Python3 and pip if not present
sudo apt install -y python3 python3-pip

# Install required Python packages
pip3 install requests beautifulsoup4 python-whois dnspython

# Create directory for the scanner
mkdir -p ~/website-scanner
cp website_scanner.py ~/website-scanner/
chmod +x ~/website-scanner/website_scanner.py

# Create symlink for easy access
sudo ln -sf ~/website-scanner/website_scanner.py /usr/local/bin/website-scanner

echo "Installation completed!"
echo "Usage: website-scanner https://example.com"
