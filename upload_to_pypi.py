#!/usr/bin/env python3
"""
Script to upload the latest version of shibudb-client to PyPI
This script automates the entire process from version bumping to upload.
"""

import os
import sys
import subprocess
import re
import argparse
from pathlib import Path

def run_command(command, description, check=True):
    """Run a command and handle errors"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=check, capture_output=True, text=True)
        if result.stdout:
            print(f"✅ {description} completed successfully")
            if result.stdout.strip():
                print(f"   Output: {result.stdout.strip()}")
        return result
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(f"   Error: {e.stderr}")
        if check:
            sys.exit(1)
        return None

def get_current_version():
    """Extract current version from setup.py"""
    try:
        with open('setup.py', 'r') as f:
            content = f.read()
            match = re.search(r"version=\"([^\"]+)\"", content)
            if match:
                return match.group(1)
    except Exception as e:
        print(f"❌ Error reading current version: {e}")
        return None

def update_version(version_type):
    """Update version in setup.py"""
    try:
        with open('setup.py', 'r') as f:
            content = f.read()
        
        # Extract current version
        match = re.search(r"version=\"([^\"]+)\"", content)
        if not match:
            print("❌ Could not find version in setup.py")
            return None
        
        current_version = match.group(1)
        print(f"📋 Current version: {current_version}")
        
        # Parse version components
        parts = current_version.split('.')
        if len(parts) != 3:
            print("❌ Invalid version format. Expected format: X.Y.Z")
            return None
        
        major, minor, patch = map(int, parts)
        
        # Update version based on type
        if version_type == 'major':
            major += 1
            minor = 0
            patch = 0
        elif version_type == 'minor':
            minor += 1
            patch = 0
        elif version_type == 'patch':
            patch += 1
        else:
            print(f"❌ Invalid version type: {version_type}")
            return None
        
        new_version = f"{major}.{minor}.{patch}"
        print(f"📈 New version: {new_version}")
        
        # Update setup.py
        new_content = re.sub(r"version=\"([^\"]+)\"", f'version="{new_version}"', content)
        
        with open('setup.py', 'w') as f:
            f.write(new_content)
        
        print(f"✅ Updated setup.py to version {new_version}")
        return new_version
        
    except Exception as e:
        print(f"❌ Error updating version: {e}")
        return None

def clean_build_files():
    """Clean previous build files"""
    print("🧹 Cleaning previous build files...")
    files_to_remove = [
        'dist/',
        'build/',
        '*.egg-info/',
        '*.egg'
    ]
    
    for pattern in files_to_remove:
        run_command(f"rm -rf {pattern}", f"Removing {pattern}", check=False)

def build_package():
    """Build the package"""
    print("🔨 Building package...")
    result = run_command("python -m build", "Building package")
    if result and result.returncode == 0:
        print("✅ Package built successfully")
        return True
    return False

def validate_package():
    """Validate the built package"""
    print("🔍 Validating package...")
    result = run_command("twine check dist/*", "Validating package")
    if result and result.returncode == 0:
        print("✅ Package validation passed")
        return True
    return False

def upload_to_pypi(test=False):
    """Upload to PyPI or TestPyPI"""
    if test:
        print("🧪 Uploading to TestPyPI...")
        result = run_command("twine upload --repository testpypi dist/*", "Uploading to TestPyPI")
    else:
        print("🚀 Uploading to PyPI...")
        result = run_command("twine upload dist/*", "Uploading to PyPI")
    
    if result and result.returncode == 0:
        if test:
            print("✅ Successfully uploaded to TestPyPI")
            print("🔗 View at: https://test.pypi.org/project/shibudb-client/")
        else:
            print("✅ Successfully uploaded to PyPI")
            print("🔗 View at: https://pypi.org/project/shibudb-client/")
        return True
    return False

def check_prerequisites():
    """Check if all required tools are installed"""
    print("🔧 Checking prerequisites...")
    
    required_tools = [
        ('python', 'Python interpreter'),
        ('pip', 'Package installer'),
        ('python -m build', 'Build tool'),
        ('twine', 'Upload tool')
    ]
    
    for tool, description in required_tools:
        result = run_command(f"{tool} --version", f"Checking {description}", check=False)
        if result and result.returncode == 0:
            print(f"✅ {description} is available")
        else:
            print(f"❌ {description} is not available")
            if 'build' in tool or tool == 'twine':
                print(f"   Install with: pip install {tool.split()[-1]}")
            return False
    
    return True

def check_git_status():
    """Check git status and warn if there are uncommitted changes"""
    print("📋 Checking git status...")
    result = run_command("git status --porcelain", "Checking git status", check=False)
    if result and result.stdout.strip():
        print("⚠️  Warning: You have uncommitted changes:")
        print(result.stdout)
        response = input("Do you want to continue anyway? (y/N): ")
        if response.lower() != 'y':
            print("❌ Aborting upload")
            sys.exit(1)
    else:
        print("✅ Working directory is clean")

def create_git_tag(version):
    """Create a git tag for the new version"""
    print(f"🏷️  Creating git tag v{version}...")
    result = run_command(f"git tag v{version}", "Creating git tag", check=False)
    if result and result.returncode == 0:
        print(f"✅ Created git tag v{version}")
        return True
    else:
        print("⚠️  Could not create git tag (this is optional)")
        return False

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Upload shibudb-client to PyPI')
    parser.add_argument('--version-type', choices=['major', 'minor', 'patch'], 
                       default='patch', help='Version increment type (default: patch)')
    parser.add_argument('--test', action='store_true', 
                       help='Upload to TestPyPI instead of PyPI')
    parser.add_argument('--no-clean', action='store_true', 
                       help='Skip cleaning build files')
    parser.add_argument('--no-version-bump', action='store_true', 
                       help='Skip version bumping')
    parser.add_argument('--no-tag', action='store_true', 
                       help='Skip creating git tag')
    
    args = parser.parse_args()
    
    print("🚀 ShibuDb Client PyPI Upload Script")
    print("=" * 50)
    
    # Check prerequisites
    if not check_prerequisites():
        print("❌ Prerequisites not met. Please install missing tools.")
        sys.exit(1)
    
    # Check git status
    check_git_status()
    
    # Get current version
    current_version = get_current_version()
    if not current_version:
        print("❌ Could not determine current version")
        sys.exit(1)
    
    print(f"📋 Current version: {current_version}")
    
    # Update version if requested
    new_version = None
    if not args.no_version_bump:
        new_version = update_version(args.version_type)
        if not new_version:
            print("❌ Failed to update version")
            sys.exit(1)
    else:
        new_version = current_version
        print(f"📋 Using current version: {new_version}")
    
    # Clean build files
    if not args.no_clean:
        clean_build_files()
    
    # Build package
    if not build_package():
        print("❌ Package build failed")
        sys.exit(1)
    
    # Validate package
    if not validate_package():
        print("❌ Package validation failed")
        sys.exit(1)
    
    # Upload to PyPI
    if not upload_to_pypi(args.test):
        print("❌ Upload failed")
        sys.exit(1)
    
    # Create git tag
    if not args.no_tag and new_version != current_version:
        create_git_tag(new_version)
    
    print("\n🎉 Upload completed successfully!")
    print(f"📦 Version: {new_version}")
    if args.test:
        print("🧪 Uploaded to TestPyPI")
        print("🔗 View at: https://test.pypi.org/project/shibudb-client/")
    else:
        print("🚀 Uploaded to PyPI")
        print("🔗 View at: https://pypi.org/project/shibudb-client/")
    
    print("\n📋 Next steps:")
    print("1. Test the installation: pip install shibudb-client")
    print("2. Update your documentation if needed")
    print("3. Create a release on GitHub if desired")

if __name__ == "__main__":
    main() 