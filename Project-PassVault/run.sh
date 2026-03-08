#!/bin/bash
# Activate virtual environment
# Run the Python app from the current directory
python "$(dirname "$0")/passVault.py"

# Keep the terminal open after the app ends
echo "Press any key to close..."
read -n 1
