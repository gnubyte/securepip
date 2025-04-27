#!/bin/bash

# Exit on error
set -e

# Function to bump version
bump_version() {
    local version_file="setup.py"
    
    # Debug: Print the file contents
    echo "Contents of setup.py:"
    cat $version_file
    
    # Try different methods to extract version
    local current_version=$(sed -n 's/.*version="\([0-9]\+\.[0-9]\+\.[0-9]\+\)".*/\1/p' $version_file)
    echo "Version extracted with sed: $current_version"
    
    # Alternative method using grep
    local current_version_grep=$(grep -o 'version="[0-9]\+\.[0-9]\+\.[0-9]\+"' $version_file | cut -d'"' -f2)
    echo "Version extracted with grep: $current_version_grep"
    
    # Use the grep version if sed failed
    if [ -z "$current_version" ]; then
        current_version=$current_version_grep
    fi
    
    # Ensure we have a valid version number
    if [[ ! $current_version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Error: Invalid version format in setup.py: $current_version"
        echo "Expected format: X.Y.Z where X, Y, and Z are numbers"
        exit 1
    fi
    
    local major=$(echo $current_version | cut -d. -f1)
    local minor=$(echo $current_version | cut -d. -f2)
    local patch=$(echo $current_version | cut -d. -f3)
    
    # Ensure version components are numbers
    if ! [[ $major =~ ^[0-9]+$ ]] || ! [[ $minor =~ ^[0-9]+$ ]] || ! [[ $patch =~ ^[0-9]+$ ]]; then
        echo "Error: Version components must be numbers"
        echo "Major: $major, Minor: $minor, Patch: $patch"
        exit 1
    fi
    
    case "$1" in
        "major")
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        "minor")
            minor=$((minor + 1))
            patch=0
            ;;
        "patch")
            patch=$((patch + 1))
            ;;
        *)
            # Default to minor version bump
            minor=$((minor + 1))
            patch=0
            ;;
    esac
    
    new_version="$major.$minor.$patch"
    
    # Verify the new version is valid
    if [[ ! $new_version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Error: Generated invalid version: $new_version"
        exit 1
    fi
    
    # Update setup.py with the new version
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s/version=\".*\"/version=\"$new_version\"/" $version_file
    else
        # Linux
        sed -i "s/version=\".*\"/version=\"$new_version\"/" $version_file
    fi
    
    echo "Version bumped from $current_version to $new_version"
}

# Parse command line arguments
BUMP_TYPE="minor"  # Default to minor version bump
while [[ $# -gt 0 ]]; do
    case "$1" in
        --major)
            BUMP_TYPE="major"
            shift
            ;;
        --minor)
            BUMP_TYPE="minor"
            shift
            ;;
        --patch)
            BUMP_TYPE="patch"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Bump version
bump_version "$BUMP_TYPE"

# Clean previous builds
rm -rf build/ dist/ *.egg-info/

# Ensure wheel is installed
pip install wheel

# Build the package
python3 setup.py bdist_wheel

# Install the package
pip install -e .

# Check if twine is installed
if ! command -v twine &> /dev/null; then
    echo "Installing twine..."
    pip install twine
fi

# Upload to PyPI
echo "Uploading to PyPI..."
twine upload dist/* --verbose

# Clean up
rm -rf build/ dist/ *.egg-info/

echo "Deployment complete!" 