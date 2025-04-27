#!/bin/bash

# Exit on error
set -e

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -e .

# Make the script executable
chmod +x securepip/cli.py

# Create symlink to make securepip available in PATH
if [ ! -f /usr/local/bin/securepip ]; then
    sudo ln -s "$(pwd)/venv/bin/securepip" /usr/local/bin/securepip
    echo "securepip installed successfully!"
else
    echo "securepip is already installed at /usr/local/bin/securepip"
fi

echo "Installation complete. You can now use 'securepip' command." 