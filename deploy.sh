#!/bin/bash

# Exit on error
set -e

# Clean previous builds
rm -rf build/ dist/ *.egg-info/

# Build the package
python3 setup.py sdist bdist_wheel

# Check if twine is installed
if ! command -v twine &> /dev/null; then
    echo "Installing twine..."
    pip install twine
fi

# Upload to PyPI
echo "Uploading to PyPI..."
twine upload dist/*

# Clean up
rm -rf build/ dist/ *.egg-info/

echo "Deployment complete!" 