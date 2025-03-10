#!/usr/bin/env python3
"""
Create distribution zip files for Integrity Assistant
"""

import os
import shutil
import zipfile
import platform

# Base directories
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_CODE = os.path.join(ROOT_DIR, "zipfilecode", "main.py")
OUTPUT_DIR = os.path.join(ROOT_DIR, "website", "public", "downloads")

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Platform-specific directories
PLATFORMS = ["win", "macos", "linux"]
TEMP_DIRS = {p: os.path.join(ROOT_DIR, f"temp-integrity-assistant-{p}") for p in PLATFORMS}

def create_readme():
    """Create README.md content"""
    return """# Integrity Assistant 1.0.2 (Public Beta)

Integrity Assistant is your digital memory assistant that continuously monitors your digital activity, making it searchable and interactive through natural language.

## Installation

1. Run the installer script for your platform:
   - Windows: Double-click `install.bat`
   - macOS/Linux: Open a terminal and run `chmod +x install.sh && ./install.sh`

2. Launch Integrity Assistant:
   - Windows: Use the desktop shortcut or run `run_integrity.bat`
   - macOS/Linux: Use the application shortcut or run `./run_integrity.sh`

## Features

- **Digital Activity Monitoring**: Captures screenshots and records keystrokes to understand your digital activity
- **Advanced OCR**: Extracts text from screenshots to make all visual content searchable
- **Natural Language Interface**: Ask questions about your activity in everyday language
- **Privacy-First Design**: All processing happens locally with military-grade encryption

## Privacy & Security

All data is encrypted using AES-256 encryption. You can enable Privacy Mode at any time to pause all monitoring.

## Support

Need help? Contact our support team:
- Email: support@integrity-assistant.com
- Website: https://integrity-assistant.com
"""

def create_requirements():
    """Create requirements.txt content"""
    return """customtkinter==5.2.2
pillow==10.2.0
opencv-python==4.9.0.80
numpy==1.24.3
easyocr==1.7.1
requests==2.31.0
pynput==1.7.6
cryptography==41.0.7
"""

def create_windows_installer():
    """Create Windows installer batch script"""
    return """@echo off
echo Integrity Assistant 1.0.2 (Public Beta) Installer
echo ===============================================
echo.

:: Check for Python installation
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed or not in the PATH.
    echo Please install Python 3.8 or higher from https://www.python.org/downloads/
    echo and make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

:: Check Python version
for /f "tokens=2" %%V in ('python -c "import sys; print(sys.version_info[0])"') do set PYTHON_MAJOR=%%V
if %PYTHON_MAJOR% lss 3 (
    echo Python 3 is required, but Python %PYTHON_MAJOR% is installed.
    echo Please install Python 3.8 or higher.
    echo.
    pause
    exit /b 1
)

echo Installing required dependencies...
echo This may take a few minutes...
echo.

:: Create and activate a virtual environment
python -m venv venv
call venv\Scripts\activate.bat

:: Upgrade pip
python -m pip install --upgrade pip

:: Install required packages
pip install -r requirements.txt

:: Check for errors during installation
if %errorlevel% neq 0 (
    echo.
    echo An error occurred during dependency installation.
    echo Please check your internet connection and try again.
    echo.
    pause
    exit /b 1
)

:: Create necessary directories
mkdir assets 2>nul
mkdir logs 2>nul
mkdir data 2>nul
mkdir screenshots 2>nul

echo.
echo Installation completed successfully!
echo.

:: Create desktop shortcut
echo Creating desktop shortcut...
set SCRIPT="%TEMP%\create_shortcut.vbs"
set DESKTOP=%USERPROFILE%\Desktop

echo Set oWS = WScript.CreateObject("WScript.Shell") > %SCRIPT%
echo sLinkFile = "%DESKTOP%\Integrity Assistant.lnk" >> %SCRIPT%
echo Set oLink = oWS.CreateShortcut(sLinkFile) >> %SCRIPT%
echo oLink.TargetPath = "%CD%\run_integrity.bat" >> %SCRIPT%
echo oLink.WorkingDirectory = "%CD%" >> %SCRIPT%
echo oLink.IconLocation = "%CD%\assets\icon.ico" >> %SCRIPT%
echo oLink.Description = "Integrity Assistant" >> %SCRIPT%
echo oLink.Save >> %SCRIPT%

cscript /nologo %SCRIPT%
del %SCRIPT%

:: Create run_integrity.bat
echo @echo off > run_integrity.bat
echo cd /d "%%~dp0" >> run_integrity.bat
echo call venv\Scripts\activate.bat >> run_integrity.bat
echo python integrity_assistant.py >> run_integrity.bat

echo.
echo You can now run Integrity Assistant from the desktop shortcut or by running run_integrity.bat
echo.

pause
"""

def create_unix_installer():
    """Create Unix (macOS/Linux) installer shell script"""
    return """#!/bin/bash

echo "Integrity Assistant 1.0.2 (Public Beta) Installer"
echo "==============================================="
echo

# Check for Python installation
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed or not in the PATH."
    echo "Please install Python 3.8 or higher."
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "For macOS, you can install it using Homebrew: brew install python3"
    else
        echo "For Ubuntu/Debian: sudo apt-get install python3 python3-pip python3-venv"
        echo "For Fedora: sudo dnf install python3 python3-pip"
    fi
    
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c "import sys; print('{}.{}'.format(sys.version_info[0], sys.version_info[1]))")
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
    echo "Python 3.8 or higher is required, but Python $PYTHON_VERSION is installed."
    echo "Please upgrade your Python installation."
    exit 1
fi

echo "Installing required dependencies..."
echo "This may take a few minutes..."
echo

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install required packages
pip install -r requirements.txt

# Check for errors during installation
if [ $? -ne 0 ]; then
    echo
    echo "An error occurred during dependency installation."
    echo "Please check your internet connection and try again."
    exit 1
fi

# Create necessary directories
mkdir -p assets
mkdir -p logs
mkdir -p data
mkdir -p screenshots

echo
echo "Installation completed successfully!"
echo

# Create run script
cat > run_integrity.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python3 integrity_assistant.py
EOF

# Make run script executable
chmod +x run_integrity.sh

# Create desktop shortcut based on platform
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    echo "Creating application shortcut..."
    
    # Create Applications directory if it doesn't exist
    mkdir -p ~/Applications
    
    # Get absolute path of the installation directory
    INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)
    
    # Create a simple AppleScript application
    cat > Integrity.applescript << EOF
tell application "Terminal"
    do script "cd \"$INSTALL_DIR\" && ./run_integrity.sh"
end tell
EOF
    
    # Compile the AppleScript
    osacompile -o ~/Applications/Integrity.app Integrity.applescript
    
    # Clean up the script
    rm Integrity.applescript
    
    echo "Shortcut created in ~/Applications/Integrity.app"
    
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    echo "Creating desktop shortcut..."
    
    # Get absolute path of the installation directory
    INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)
    
    # Create .desktop file
    mkdir -p ~/.local/share/applications
    cat > ~/.local/share/applications/integrity-assistant.desktop << EOF
[Desktop Entry]
Type=Application
Name=Integrity Assistant
Comment=Digital Activity Assistant
Exec=$INSTALL_DIR/run_integrity.sh
Terminal=false
Categories=Utility;
EOF
    
    echo "Desktop shortcut created."
fi

echo
echo "You can now run Integrity Assistant by executing ./run_integrity.sh"
echo "or by using the shortcut created on your desktop/applications menu."
echo

# Make the script executable
chmod +x run_integrity.sh
"""

def create_platform_directory(platform):
    """Create a platform-specific directory with all necessary files"""
    platform_dir = TEMP_DIRS[platform]
    
    # Remove existing directory if it exists
    if os.path.exists(platform_dir):
        shutil.rmtree(platform_dir)
    
    # Create directory structure
    os.makedirs(platform_dir)
    os.makedirs(os.path.join(platform_dir, "assets"))
    
    # Copy the main Python file and rename it
    shutil.copy(SOURCE_CODE, os.path.join(platform_dir, "integrity_assistant.py"))
    
    # Create README.md
    with open(os.path.join(platform_dir, "README.md"), "w") as f:
        f.write(create_readme())
    
    # Create requirements.txt
    with open(os.path.join(platform_dir, "requirements.txt"), "w") as f:
        f.write(create_requirements())
    
    # Create installer script
    if platform == "win":
        with open(os.path.join(platform_dir, "install.bat"), "w") as f:
            f.write(create_windows_installer())
    else:  # macOS or Linux
        installer_path = os.path.join(platform_dir, "install.sh")
        with open(installer_path, "w") as f:
            f.write(create_unix_installer())
        # Make the shell script executable
        os.chmod(installer_path, 0o755)
    
    # Create placeholder icon files (you should replace these with actual icons)
    icon_placeholder = "# This is a placeholder for an icon file\n# Replace with actual icon files"
    
    if platform == "win":
        with open(os.path.join(platform_dir, "assets", "icon.ico"), "w") as f:
            f.write(icon_placeholder)
    
    with open(os.path.join(platform_dir, "assets", "icon.png"), "w") as f:
        f.write(icon_placeholder)
    
    print(f"Created platform directory for {platform}")
    
    return platform_dir

def create_zip_file(platform):
    """Create a zip file for the specified platform"""
    platform_dir = TEMP_DIRS[platform]
    zip_filename = f"integrity-assistant-{platform}.zip"
    zip_path = os.path.join(OUTPUT_DIR, zip_filename)
    
    # Remove existing zip if it exists
    if os.path.exists(zip_path):
        os.remove(zip_path)
    
    # Create zip file
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(platform_dir):
            for file in files:
                file_path = os.path.join(root, file)
                # Add file to zip with relative path
                arcname = os.path.join(os.path.basename(platform_dir), os.path.relpath(file_path, platform_dir))
                zipf.write(file_path, arcname)
    
    print(f"Created zip file: {zip_path}")
    return zip_path

def cleanup():
    """Remove temporary directories"""
    for platform in PLATFORMS:
        if os.path.exists(TEMP_DIRS[platform]):
            shutil.rmtree(TEMP_DIRS[platform])
    print("Cleaned up temporary directories")

def main():
    """Main function to create all zip files"""
    print("Creating distribution zip files for Integrity Assistant")
    print("=" * 60)
    
    try:
        # Create platform directories and zip files
        for platform in PLATFORMS:
            create_platform_directory(platform)
            create_zip_file(platform)
        
        # Clean up temporary directories
        cleanup()
        
        print("\nSuccess! All zip files created and placed in website/public/downloads/")
        print("You can now deploy your website to make the downloads available.")
    
    except Exception as e:
        print(f"Error: {str(e)}")
        cleanup()
        return 1
    
    return 0

if __name__ == "__main__":
    main()