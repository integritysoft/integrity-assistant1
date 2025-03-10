#!/usr/bin/env python3
"""
Integrity Assistant Beta 1.0.2 (Public)

A digital activity assistant that monitors screen activity and keystrokes,
extracting text and context to provide a searchable record of your digital life.

This single file contains all components of the application:
- Configuration management
- Authentication with Supabase
- Screenshot capture and OCR
- Keystroke logging
- Data management
- Server communication
- GUI interface

Run this file directly to start the application.
"""

import os
import sys
import time
import json
import logging
import logging.handlers
import threading
import queue
import traceback
import platform
import uuid
import shutil
import base64
import glob
import re
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import messagebox, PhotoImage
import webbrowser
import requests

# Try to import required third-party libraries
try:
    # GUI library
    import customtkinter as ctk
    # Image processing
    import cv2
    import numpy as np
    from PIL import ImageGrab, Image
    # OCR processing
    import easyocr
    # Keystroke monitoring
    from pynput import keyboard
    # Encryption
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError as e:
    # Show error message if dependencies aren't installed
    print(f"Error: Missing required dependencies. Please run installer first.")
    print(f"Missing: {str(e)}")
    print("\nPlease run the installer script (install.bat or install.sh) to set up all dependencies.")
    sys.exit(1)

# Set appearance mode and default theme for GUI
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

#########################################
# UTILITY FUNCTIONS
#########################################

def setup_logging(log_level=logging.INFO, log_file=None):
    """Set up application logging"""
    # Get the main logger
    logger = logging.getLogger("integrity")
    logger.setLevel(log_level)
    
    # Clear any existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(formatter)
    
    # Add console handler to logger
    logger.addHandler(console_handler)
    
    # Add file handler if specified
    if log_file:
        # Create logs directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Set up rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=3
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        
        # Add file handler to logger
        logger.addHandler(file_handler)
    
    return logger

def derive_key(password, salt=None):
    """Derive encryption key from password"""
    if salt is None:
        # Generate a salt if not provided
        salt = os.urandom(16)
    
    # Use PBKDF2 to derive a key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    return key, salt

def encrypt_data(data, key):
    """Encrypt data using Fernet symmetric encryption"""
    try:
        if isinstance(key, str):
            # Convert string key to bytes and ensure it's valid for Fernet
            key_bytes = key.encode()
            # Ensure key is URL-safe base64-encoded and 32 bytes long
            if len(key_bytes) != 32:
                key_bytes, _ = derive_key(key)
        else:
            key_bytes = key
        
        # Create Fernet cipher
        cipher = Fernet(key_bytes)
        
        # Encrypt data
        encrypted_data = cipher.encrypt(data.encode())
        
        return encrypted_data
    
    except Exception as e:
        logger = logging.getLogger("integrity.utils")
        logger.error(f"Encryption error: {str(e)}")
        logger.error(traceback.format_exc())
        return None

def decrypt_data(encrypted_data, key):
    """Decrypt data using Fernet symmetric encryption"""
    try:
        if isinstance(key, str):
            # Convert string key to bytes and ensure it's valid for Fernet
            key_bytes = key.encode()
            # Ensure key is URL-safe base64-encoded and 32 bytes long
            if len(key_bytes) != 32:
                key_bytes, _ = derive_key(key)
        else:
            key_bytes = key
        
        # Create Fernet cipher
        cipher = Fernet(key_bytes)
        
        # Decrypt data
        decrypted_data = cipher.decrypt(encrypted_data).decode()
        
        return decrypted_data
    
    except Exception as e:
        logger = logging.getLogger("integrity.utils")
        logger.error(f"Decryption error: {str(e)}")
        logger.error(traceback.format_exc())
        return None

def format_size(size_bytes):
    """Format byte size into human-readable format"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

def generate_machine_id():
    """Generate a unique machine ID for this installation"""
    try:
        # Try to get a hardware-based ID
        if platform.system() == "Windows":
            import subprocess
            result = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
            return result
        elif platform.system() == "Darwin":  # macOS
            import subprocess
            result = subprocess.check_output(['/usr/sbin/ioreg', '-rd1', '-c', 'IOPlatformExpertDevice']).decode()
            uuid_match = re.search(r'IOPlatformUUID.*?\"(.+?)\"', result)
            if uuid_match:
                return uuid_match.group(1)
        elif platform.system() == "Linux":
            try:
                # Try to use /etc/machine-id
                with open('/etc/machine-id', 'r') as f:
                    return f.read().strip()
            except:
                # Fall back to using /var/lib/dbus/machine-id
                with open('/var/lib/dbus/machine-id', 'r') as f:
                    return f.read().strip()
    except:
        pass
    
    # Fallback to a generated UUID stored locally
    id_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.machine_id')
    if os.path.exists(id_file):
        with open(id_file, 'r') as f:
            return f.read().strip()
    else:
        # Generate a new UUID
        machine_id = str(uuid.uuid4())
        try:
            with open(id_file, 'w') as f:
                f.write(machine_id)
        except:
            pass
        return machine_id

#########################################
# CONFIGURATION MANAGEMENT
#########################################

# Default configuration values
DEFAULT_CONFIG = {
    # Application settings
    "app_name": "Integrity Assistant",
    "app_version": "1.0.2",
    "app_status": "Beta (Public)",
    
    # Server settings
    "supabase_url": "https://qamcmtaupcztangqvhkz.supabase.co",
    "supabase_key": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFhbWNtdGF1cGN6dGFuZ3F2aGt6Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDEyMzc0MTMsImV4cCI6MjA1NjgxMzQxM30.UWinrT5vTh0P7GcXRL2dgP6IEkPQ83Ur1kghe-lm1Mg",
    "server_url": "https://integrity-assistant.up.railway.app/api",
    
    # Data collection settings
    "screenshot_interval": 0.5,  # 2 screenshots per second
    "monitor_all": True,         # Monitor all screens
    "ocr_enabled": True,         # Enable text extraction via OCR
    "keylogger_enabled": True,   # Enable keystroke logging
    
    # Data retention settings
    "retention_days": 7,         # Keep data locally for 7 days
    "store_screenshots": True,   # Store one screenshot per minute
    
    # Privacy settings
    "excluded_apps": [],         # Apps to exclude from monitoring
    "excluded_sites": [],        # Websites to exclude from monitoring
    "privacy_mode_hotkey": "ctrl+shift+p",  # Hotkey to toggle privacy mode
    
    # User settings
    "theme": "dark",             # UI theme (dark/light)
    "startup": True,             # Run on system startup
    "minimize_to_tray": True,    # Minimize to system tray
    
    # Paths (will be set in runtime)
    "data_dir": "",              # Main data directory
    "screenshots_dir": "",       # Screenshots directory
    "logs_dir": "",              # Logs directory
    
    # Security
    "encryption_key": "",        # Generated on first run
    
    # Logging
    "log_level": "INFO",         # DEBUG, INFO, WARNING, ERROR, CRITICAL
    "log_file_size": 5,          # Max log file size in MB
    "log_file_count": 3,         # Number of backup log files
}

class Config:
    """Configuration manager for Integrity Assistant"""
    
    def __init__(self):
        """Initialize configuration"""
        self.logger = logging.getLogger("integrity.config")
        self.config_data = DEFAULT_CONFIG.copy()
        
        # Set up paths based on OS
        self._setup_paths()
        
        # Load existing config or create new one
        self._load_config()
        
        # Ensure encryption key exists
        if not self.config_data.get("encryption_key"):
            self.config_data["encryption_key"] = str(uuid.uuid4())
            self._save_config()
        
        self.logger.debug("Configuration initialized")
    
    def _setup_paths(self):
        """Set up data paths based on operating system"""
        system = platform.system()
        home_dir = os.path.expanduser("~")
        
        if system == "Windows":
            base_dir = os.path.join(home_dir, "AppData", "Local", "IntegrityAssistant")
        elif system == "Darwin":  # macOS
            base_dir = os.path.join(home_dir, "Library", "Application Support", "IntegrityAssistant")
        else:  # Linux/Unix
            base_dir = os.path.join(home_dir, ".integrity-assistant")
        
        # Create directories if they don't exist
        os.makedirs(base_dir, exist_ok=True)
        
        # Set paths in config
        self.config_data["data_dir"] = os.path.join(base_dir, "data")
        self.config_data["screenshots_dir"] = os.path.join(base_dir, "screenshots")
        self.config_data["logs_dir"] = os.path.join(base_dir, "logs")
        
        # Create subdirectories
        os.makedirs(self.config_data["data_dir"], exist_ok=True)
        os.makedirs(self.config_data["screenshots_dir"], exist_ok=True)
        os.makedirs(self.config_data["logs_dir"], exist_ok=True)
        
        # Set config file path
        self.config_file = os.path.join(base_dir, "config.json")
    
    def _load_config(self):
        """Load configuration from file or create default config"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    
                    # Update config with loaded values but preserve defaults for new options
                    for key, value in loaded_config.items():
                        self.config_data[key] = value
                    
                self.logger.debug("Configuration loaded from file")
            else:
                self._save_config()
                self.logger.debug("Created new configuration file")
        except Exception as e:
            self.logger.error(f"Error loading configuration: {str(e)}")
            self._save_config()
    
    def _save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config_data, f, indent=4)
            self.logger.debug("Configuration saved to file")
        except Exception as e:
            self.logger.error(f"Error saving configuration: {str(e)}")
    
    def get(self, key, default=None):
        """Get a configuration value"""
        return self.config_data.get(key, default)
    
    def set(self, key, value):
        """Set a configuration value and save"""
        self.config_data[key] = value
        self._save_config()
    
    def update(self, config_dict):
        """Update multiple configuration values at once"""
        self.config_data.update(config_dict)
        self._save_config()
    
    def get_all(self):
        """Get all configuration values"""
        return self.config_data.copy()
    
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        # Keep the paths and encryption key
        data_dir = self.config_data.get("data_dir")
        screenshots_dir = self.config_data.get("screenshots_dir")
        logs_dir = self.config_data.get("logs_dir")
        encryption_key = self.config_data.get("encryption_key")
        
        # Reset to defaults
        self.config_data = DEFAULT_CONFIG.copy()
        
        # Restore paths and key
        self.config_data["data_dir"] = data_dir
        self.config_data["screenshots_dir"] = screenshots_dir
        self.config_data["logs_dir"] = logs_dir
        self.config_data["encryption_key"] = encryption_key
        
        self._save_config()
        self.logger.info("Configuration reset to defaults")

#########################################
# AUTHENTICATION
#########################################

class SupabaseAuth:
    """Authentication manager for Supabase"""
    
    def __init__(self, supabase_url, supabase_key):
        """Initialize the authentication manager"""
        self.logger = logging.getLogger("integrity.auth")
        self.supabase_url = supabase_url
        self.supabase_key = supabase_key
        
        # Auth state
        self.user_data = None
        self.access_token = None
        self.refresh_token = None
        self.expires_at = None
        
        # Auth persistence
        self.auth_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            ".auth_cache"
        )
        
        # Load any stored credentials
        self._load_auth_data()
        
        # Start token refresh thread if we have credentials
        if self.is_authenticated():
            self._start_token_refresh_thread()
    
    def is_authenticated(self):
        """Check if user is authenticated"""
        if not self.access_token or not self.expires_at:
            return False
        
        # Check if token is expired
        now = datetime.now()
        expiry = datetime.fromtimestamp(self.expires_at)
        
        return now < expiry
    
    def login(self, email, password):
        """Login with email and password"""
        try:
            url = f"{self.supabase_url}/auth/v1/token?grant_type=password"
            headers = {
                "apikey": self.supabase_key,
                "Content-Type": "application/json"
            }
            data = {
                "email": email,
                "password": password
            }
            
            response = requests.post(url, headers=headers, json=data)
            
            if response.status_code == 200:
                auth_data = response.json()
                
                # Store auth data
                self.access_token = auth_data.get("access_token")
                self.refresh_token = auth_data.get("refresh_token")
                self.expires_at = time.time() + auth_data.get("expires_in", 3600)
                
                # Get user data
                self.user_data = auth_data.get("user", {})
                
                # Save auth data
                self._save_auth_data()
                
                # Start token refresh thread
                self._start_token_refresh_thread()
                
                self.logger.info(f"User {email} logged in successfully")
                return True, "Login successful"
            else:
                error_msg = response.json().get("error_description", "Login failed")
                self.logger.error(f"Login failed: {error_msg}")
                return False, error_msg
        
        except Exception as e:
            self.logger.error(f"Login error: {str(e)}")
            return False, "Connection error. Please check your internet connection."
    
    def register(self, email, password, full_name):
        """Register a new user"""
        try:
            url = f"{self.supabase_url}/auth/v1/signup"
            headers = {
                "apikey": self.supabase_key,
                "Content-Type": "application/json"
            }
            data = {
                "email": email,
                "password": password,
                "data": {
                    "full_name": full_name
                }
            }
            
            response = requests.post(url, headers=headers, json=data)
            
            if response.status_code == 200:
                auth_data = response.json()
                
                # Store auth data
                self.access_token = auth_data.get("access_token")
                self.refresh_token = auth_data.get("refresh_token")
                self.expires_at = time.time() + auth_data.get("expires_in", 3600)
                
                # Get user data
                self.user_data = auth_data.get("user", {})
                
                # Add the display name to user_data if not present
                if not self.user_data.get("user_metadata", {}).get("full_name"):
                    self.user_data.setdefault("user_metadata", {})["full_name"] = full_name
                
                # Save auth data
                self._save_auth_data()
                
                # Start token refresh thread
                self._start_token_refresh_thread()
                
                self.logger.info(f"User {email} registered successfully")
                return True, "Registration successful"
            else:
                error_msg = response.json().get("error_description", "Registration failed")
                self.logger.error(f"Registration failed: {error_msg}")
                return False, error_msg
        
        except Exception as e:
            self.logger.error(f"Registration error: {str(e)}")
            return False, "Connection error. Please check your internet connection."
    
    def logout(self):
        """Logout the current user"""
        try:
            if self.access_token:
                url = f"{self.supabase_url}/auth/v1/logout"
                headers = {
                    "apikey": self.supabase_key,
                    "Authorization": f"Bearer {self.access_token}",
                    "Content-Type": "application/json"
                }
                
                response = requests.post(url, headers=headers)
                
                # Clear auth data regardless of response
                self.access_token = None
                self.refresh_token = None
                self.expires_at = None
                self.user_data = None
                
                # Delete auth data file
                if os.path.exists(self.auth_file):
                    os.remove(self.auth_file)
                
                self.logger.info("User logged out successfully")
                return True
            
            return False
        
        except Exception as e:
            self.logger.error(f"Logout error: {str(e)}")
            
            # Still clear local data
            self.access_token = None
            self.refresh_token = None
            self.expires_at = None
            self.user_data = None
            
            # Delete auth data file
            if os.path.exists(self.auth_file):
                os.remove(self.auth_file)
            
            return False
    
    def get_user_info(self):
        """Get current user information"""
        if not self.is_authenticated() or not self.user_data:
            return None
        
        # Extract user metadata
        user_metadata = self.user_data.get("user_metadata", {})
        
        # Create a user info object
        user_info = {
            "id": self.user_data.get("id"),
            "email": self.user_data.get("email"),
            "name": user_metadata.get("full_name", "User")
        }
        
        return user_info
    
    def get_auth_header(self):
        """Get the authentication header for API requests"""
        if not self.is_authenticated():
            return None
        
        return {
            "apikey": self.supabase_key,
            "Authorization": f"Bearer {self.access_token}"
        }
    
    def _refresh_token(self):
        """Refresh the access token using the refresh token"""
        try:
            if not self.refresh_token:
                self.logger.error("No refresh token available")
                return False
            
            url = f"{self.supabase_url}/auth/v1/token?grant_type=refresh_token"
            headers = {
                "apikey": self.supabase_key,
                "Content-Type": "application/json"
            }
            data = {
                "refresh_token": self.refresh_token
            }
            
            response = requests.post(url, headers=headers, json=data)
            
            if response.status_code == 200:
                auth_data = response.json()
                
                # Update tokens
                self.access_token = auth_data.get("access_token")
                self.refresh_token = auth_data.get("refresh_token")
                self.expires_at = time.time() + auth_data.get("expires_in", 3600)
                
                # Save updated tokens
                self._save_auth_data()
                
                self.logger.debug("Token refreshed successfully")
                return True
            else:
                self.logger.error("Failed to refresh token")
                return False
        
        except Exception as e:
            self.logger.error(f"Token refresh error: {str(e)}")
            return False
    
    def _start_token_refresh_thread(self):
        """Start a thread to refresh the token periodically"""
        def refresh_loop():
            while self.is_authenticated():
                # Sleep until 5 minutes before expiry
                now = datetime.now()
                expiry = datetime.fromtimestamp(self.expires_at)
                sleep_time = (expiry - now - timedelta(minutes=5)).total_seconds()
                
                if sleep_time > 0:
                    time.sleep(sleep_time)
                
                # Refresh token if still authenticated
                if self.is_authenticated():
                    self._refresh_token()
                else:
                    break
        
        # Start thread
        refresh_thread = threading.Thread(target=refresh_loop, daemon=True)
        refresh_thread.start()
    
    def _save_auth_data(self):
        """Save authentication data to a file"""
        try:
            auth_data = {
                "access_token": self.access_token,
                "refresh_token": self.refresh_token,
                "expires_at": self.expires_at,
                "user_data": self.user_data
            }
            
            with open(self.auth_file, "w") as f:
                json.dump(auth_data, f)
            
            # Set file permissions to be readable only by the user
            os.chmod(self.auth_file, 0o600)
            
            self.logger.debug("Auth data saved to file")
        
        except Exception as e:
            self.logger.error(f"Error saving auth data: {str(e)}")
    
    def _load_auth_data(self):
        """Load authentication data from file"""
        try:
            if os.path.exists(self.auth_file):
                with open(self.auth_file, "r") as f:
                    auth_data = json.load(f)
                
                self.access_token = auth_data.get("access_token")
                self.refresh_token = auth_data.get("refresh_token")
                self.expires_at = auth_data.get("expires_at")
                self.user_data = auth_data.get("user_data")
                
                self.logger.debug("Auth data loaded from file")
                
                # Refresh token if it's close to expiry
                if self.is_authenticated():
                    now = datetime.now()
                    expiry = datetime.fromtimestamp(self.expires_at)
                    
                    if (expiry - now) < timedelta(minutes=10):
                        self._refresh_token()
        
        except Exception as e:
            self.logger.error(f"Error loading auth data: {str(e)}")
            # Reset auth data
            self.access_token = None
            self.refresh_token = None
            self.expires_at = None
            self.user_data = None

#########################################
# SERVER COMMUNICATION
#########################################

class ServerCommunication:
    """Manages communication with the Integrity server"""
    
    def __init__(self, server_url, auth):
        """Initialize server communication"""
        self.logger = logging.getLogger("integrity.server_comms")
        self.server_url = server_url
        self.auth = auth
        
        # Session for connection pooling
        self.session = requests.Session()
        
        # Set default headers
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "IntegrityAssistant/1.0.2",
        })
        
        # Last connectivity check
        self.last_check_time = 0
        self.last_check_result = False
        
        # Machine ID
        self.machine_id = os.environ.get("INTEGRITY_MACHINE_ID", "unknown")
        
        self.logger.info("Server communication initialized")
    
    def stop(self):
        """Clean up resources"""
        self.session.close()
        self.logger.info("Server communication stopped")
    
    def check_connectivity(self):
        """Check if server is reachable"""
        # Cache check results for 30 seconds to avoid excessive requests
        current_time = time.time()
        if current_time - self.last_check_time < 30:
            return self.last_check_result
        
        try:
            # Check if we're authenticated
            if not self.auth.is_authenticated():
                self.last_check_time = current_time
                self.last_check_result = False
                return False
            
            # Get auth headers
            headers = self.auth.get_auth_header()
            if not headers:
                self.last_check_time = current_time
                self.last_check_result = False
                return False
            
            # Make a lightweight ping request
            url = f"{self.server_url}/ping"
            response = self.session.get(
                url,
                headers=headers,
                timeout=5
            )
            
            # Update last check
            self.last_check_time = current_time
            self.last_check_result = response.status_code == 200
            
            return self.last_check_result
        
        except Exception as e:
            self.logger.error(f"Connectivity check error: {str(e)}")
            
            # Update last check
            self.last_check_time = current_time
            self.last_check_result = False
            
            return False
    
    def send_data(self, data):
        """Send data to the server API"""
        try:
            # Check if we're authenticated
            if not self.auth.is_authenticated():
                self.logger.error("Cannot send data: Not authenticated")
                return False
            
            # Get auth headers
            headers = self.auth.get_auth_header()
            if not headers:
                self.logger.error("Cannot send data: No auth headers")
                return False
            
            # Send data to API
            url = f"{self.server_url}/data"
            response = self.session.post(
                url,
                headers=headers,
                data=data,
                timeout=10
            )
            
            if response.status_code != 200:
                self.logger.error(f"Failed to send data: HTTP {response.status_code}")
                return False
            
            return True
        
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Data send error: {str(e)}")
            return False
        
        except Exception as e:
            self.logger.error(f"Unexpected error sending data: {str(e)}")
            self.logger.error(traceback.format_exc())
            return False
    
    def query_activity(self, query, callback=None):
        """Query the activity data with natural language"""
        try:
            # Check if we're authenticated
            if not self.auth.is_authenticated():
                self.logger.error("Cannot query activity: Not authenticated")
                if callback:
                    callback({
                        "status": "error",
                        "error": "Not authenticated"
                    })
                return False
            
            # Get auth headers
            headers = self.auth.get_auth_header()
            if not headers:
                self.logger.error("Cannot query activity: No auth headers")
                if callback:
                    callback({
                        "status": "error",
                        "error": "Authentication error"
                    })
                return False
            
            # Prepare query data
            query_data = {
                "query": query,
                "machine_id": self.machine_id,
                "timestamp": datetime.now().isoformat()
            }
            
            # Convert to JSON
            json_data = json.dumps(query_data)
            
            # Use threading to avoid blocking the UI
            def query_thread():
                try:
                    # Send query to API
                    url = f"{self.server_url}/query"
                    response = self.session.post(
                        url,
                        headers=headers,
                        data=json_data,
                        timeout=30
                    )
                    
                    if response.status_code != 200:
                        self.logger.error(f"Query failed: HTTP {response.status_code}")
                        if callback:
                            callback({
                                "status": "error",
                                "error": f"Server error (HTTP {response.status_code})"
                            })
                        return
                    
                    # Parse response
                    response_data = response.json()
                    
                    # Handle response
                    if callback:
                        callback(response_data)
                
                except requests.exceptions.RequestException as e:
                    self.logger.error(f"Query request error: {str(e)}")
                    if callback:
                        callback({
                            "status": "error",
                            "error": "Connection error"
                        })
                
                except Exception as e:
                    self.logger.error(f"Unexpected error in query: {str(e)}")
                    self.logger.error(traceback.format_exc())
                    if callback:
                        callback({
                            "status": "error",
                            "error": "An unexpected error occurred"
                        })
            
            # Start query thread
            threading.Thread(target=query_thread, daemon=True).start()
            return True
        
        except Exception as e:
            self.logger.error(f"Error preparing query: {str(e)}")
            self.logger.error(traceback.format_exc())
            if callback:
                callback({
                    "status": "error",
                    "error": "An unexpected error occurred"
                })
            return False

#########################################
# SCREENSHOT MANAGER
#########################################

class ScreenshotManager:
    """Manages screenshot capture and processing"""
    
    def __init__(self, data_queue, screenshots_dir, capture_interval=0.5):
        """Initialize the screenshot manager"""
        self.logger = logging.getLogger("integrity.screenshot")
        self.data_queue = data_queue
        self.screenshots_dir = screenshots_dir
        self.capture_interval = capture_interval
        
        # Create screenshots directory if it doesn't exist
        os.makedirs(self.screenshots_dir, exist_ok=True)
        
        # OCR reader (lazy initialized)
        self.reader = None
        
        # Running state
        self.running = False
        self.paused = False
        self.capture_thread = None
        
        # Last captured full screenshot and timestamp
        self.last_full_screenshot = None
        self.last_full_screenshot_time = None
        
        # Settings
        self.ocr_enabled = True
        self.monitor_all = True
        self.store_screenshots = True
        
        # Minute marker for storing one screenshot per minute
        self.current_minute = None
        
        self.logger.info("Screenshot manager initialized")
    
    def start(self):
        """Start screenshot capture thread"""
        if self.running:
            return
        
        self.running = True
        self.paused = False
        
        # Initialize OCR if enabled
        if self.ocr_enabled and not self.reader:
            self._init_ocr()
        
        # Start capture thread
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        
        self.logger.info("Screenshot capture started")
    
    def stop(self):
        """Stop screenshot capture thread"""
        self.running = False
        
        if self.capture_thread:
            self.capture_thread.join(timeout=1.0)
            self.capture_thread = None
        
        self.logger.info("Screenshot capture stopped")
    
    def pause(self):
        """Pause screenshot capture"""
        self.paused = True
        self.logger.info("Screenshot capture paused")
    
    def resume(self):
        """Resume screenshot capture"""
        self.paused = False
        self.logger.info("Screenshot capture resumed")
    
    def update_settings(self, ocr_enabled=None, monitor_all=None, store_screenshots=None):
        """Update screenshot manager settings"""
        if ocr_enabled is not None:
            self.ocr_enabled = ocr_enabled
            
            # Initialize OCR if needed
            if self.ocr_enabled and not self.reader:
                self._init_ocr()
        
        if monitor_all is not None:
            self.monitor_all = monitor_all
        
        if store_screenshots is not None:
            self.store_screenshots = store_screenshots
        
        self.logger.debug(f"Settings updated: OCR={self.ocr_enabled}, "
                         f"Monitor All={self.monitor_all}, "
                         f"Store Screenshots={self.store_screenshots}")
    
    def _init_ocr(self):
        """Initialize OCR reader"""
        try:
            self.logger.info("Initializing OCR reader...")
            self.reader = easyocr.Reader(['en'], gpu=False)
            self.logger.info("OCR reader initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize OCR: {str(e)}")
            self.ocr_enabled = False
    
    def _capture_loop(self):
        """Main screenshot capture loop"""
        last_capture_time = 0
        
        while self.running:
            try:
                # Check if paused
                if self.paused:
                    time.sleep(0.1)
                    continue
                
                # Throttle captures to the specified interval
                current_time = time.time()
                if current_time - last_capture_time < self.capture_interval:
                    time.sleep(0.01)
                    continue
                
                # Capture screenshot
                screenshot = self._capture_screenshot()
                
                if screenshot is None:
                    time.sleep(0.1)
                    continue
                
                # Process screenshot
                self._process_screenshot(screenshot)
                
                # Update last capture time
                last_capture_time = time.time()
                
            except Exception as e:
                self.logger.error(f"Error in screenshot capture loop: {str(e)}")
                self.logger.error(traceback.format_exc())
                time.sleep(1.0)  # Sleep to avoid spamming errors
    
    def _capture_screenshot(self):
        """Capture a screenshot"""
        try:
            # Capture screen
            screenshot = ImageGrab.grab(all_screens=self.monitor_all)
            
            # Convert to NumPy array
            screenshot_np = np.array(screenshot)
            
            # Store for future reference
            self.last_full_screenshot = screenshot_np
            self.last_full_screenshot_time = datetime.now()
            
            return screenshot_np
        
        except Exception as e:
            self.logger.error(f"Screenshot capture error: {str(e)}")
            return None
    
    def _process_screenshot(self, screenshot):
        """Process a captured screenshot"""
        timestamp = datetime.now()
        
        try:
            # Check if we need to store this screenshot (one per minute)
            minute_marker = timestamp.strftime("%Y-%m-%d-%H-%M")
            
            if self.store_screenshots and minute_marker != self.current_minute:
                self.current_minute = minute_marker
                self._store_screenshot(screenshot, timestamp)
            
            # Extract text if OCR is enabled
            if self.ocr_enabled and self.reader:
                # Convert BGR to RGB (EasyOCR works with RGB)
                screenshot_rgb = cv2.cvtColor(screenshot, cv2.COLOR_BGR2RGB)
                
                # Extract text
                text_results = self.reader.readtext(screenshot_rgb)
                
                # Process OCR results
                self._process_ocr_results(text_results, timestamp)
            
            # Create activity record with metadata
            activity_data = {
                "type": "screenshot",
                "timestamp": timestamp.isoformat(),
                "has_text": self.ocr_enabled and bool(text_results) if self.ocr_enabled else False,
                "screen_dimensions": screenshot.shape,
                "machine_id": os.environ.get("INTEGRITY_MACHINE_ID", "unknown")
            }
            
            # Add to data queue
            self.data_queue.put(activity_data)
            
        except Exception as e:
            self.logger.error(f"Screenshot processing error: {str(e)}")
            self.logger.error(traceback.format_exc())
    
    def _store_screenshot(self, screenshot, timestamp):
        """Store a screenshot to disk"""
        try:
            # Create filename based on timestamp
            filename = f"screenshot_{timestamp.strftime('%Y-%m-%d-%H-%M-%S')}.jpg"
            filepath = os.path.join(self.screenshots_dir, filename)
            
            # Convert to PIL Image for saving
            img = Image.fromarray(screenshot)
            
            # Save with compression
            img.save(filepath, quality=85, optimize=True)
            
            self.logger.debug(f"Screenshot saved: {filepath}")
            
            return filepath
        
        except Exception as e:
            self.logger.error(f"Error saving screenshot: {str(e)}")
            return None
    
    def _process_ocr_results(self, text_results, timestamp):
        """Process OCR text extraction results"""
        if not text_results:
            return
        
        try:
            # Extract text content with bounding boxes
            extracted_text = []
            
            for detection in text_results:
                bbox = detection[0]  # Bounding box coordinates
                text = detection[1]  # Text content
                confidence = detection[2]  # Confidence score
                
                # Only include text with reasonable confidence
                if confidence > 0.5 and text.strip():
                    extracted_text.append({
                        "text": text,
                        "bbox": bbox,
                        "confidence": float(confidence)
                    })
            
            # Skip if no valid text found
            if not extracted_text:
                return
            
            # Create OCR data record
            ocr_data = {
                "type": "ocr_text",
                "timestamp": timestamp.isoformat(),
                "extracted_text": extracted_text,
                "machine_id": os.environ.get("INTEGRITY_MACHINE_ID", "unknown")
            }
            
            # Add to data queue
            self.data_queue.put(ocr_data)
            
        except Exception as e:
            self.logger.error(f"OCR processing error: {str(e)}")
            self.logger.error(traceback.format_exc())
    
    def get_current_screenshot(self):
        """Get the most recent screenshot"""
        return self.last_full_screenshot, self.last_full_screenshot_time

#########################################
# KEYLOGGER
#########################################

class KeyLogger:
    """Manages keyboard input capture and processing"""
    
    def __init__(self, data_queue):
        """Initialize the keylogger"""
        self.logger = logging.getLogger("integrity.keylogger")
        self.data_queue = data_queue
        
        # Running state
        self.running = False
        self.paused = False
        self.listener = None
        
        # Buffer for keystrokes
        self.buffer = []
        self.buffer_lock = threading.Lock()
        self.last_flush_time = time.time()
        
        # Special keys mapping
        self.special_keys = {
            keyboard.Key.space: " ",
            keyboard.Key.enter: "\\n",
            keyboard.Key.tab: "\\t",
            keyboard.Key.backspace: "\\b",
            keyboard.Key.delete: "\\d",
            keyboard.Key.shift: "\\s",
            keyboard.Key.shift_r: "\\s",
            keyboard.Key.alt: "\\a",
            keyboard.Key.alt_r: "\\a",
            keyboard.Key.ctrl: "\\c",
            keyboard.Key.ctrl_r: "\\c",
            keyboard.Key.cmd: "\\cmd",
            keyboard.Key.cmd_r: "\\cmd",
            keyboard.Key.caps_lock: "\\caps",
            keyboard.Key.esc: "\\esc",
            keyboard.Key.up: "\\up",
            keyboard.Key.down: "\\down",
            keyboard.Key.left: "\\left",
            keyboard.Key.right: "\\right",
            keyboard.Key.page_up: "\\pup",
            keyboard.Key.page_down: "\\pdown",
            keyboard.Key.home: "\\home",
            keyboard.Key.end: "\\end",
            keyboard.Key.insert: "\\ins",
            keyboard.Key.f1: "\\f1",
            keyboard.Key.f2: "\\f2",
            keyboard.Key.f3: "\\f3",
            keyboard.Key.f4: "\\f4",
            keyboard.Key.f5: "\\f5",
            keyboard.Key.f6: "\\f6",
            keyboard.Key.f7: "\\f7",
            keyboard.Key.f8: "\\f8",
            keyboard.Key.f9: "\\f9",
            keyboard.Key.f10: "\\f10",
            keyboard.Key.f11: "\\f11",
            keyboard.Key.f12: "\\f12",
        }
        
        # Settings
        self.enabled = True
        
        # Start buffer flush timer thread
        self.buffer_thread = threading.Thread(target=self._buffer_flush_loop, daemon=True)
        self.buffer_thread.start()
        
        self.logger.info("Keylogger initialized")
    
    def start(self):
        """Start keylogger"""
        if not self.enabled:
            self.logger.info("Keylogger disabled in settings, not starting")
            return
            
        if self.running:
            return
        
        self.running = True
        self.paused = False
        
        try:
            # Start keyboard listener
            self.listener = keyboard.Listener(
                on_press=self._on_key_press,
                on_release=self._on_key_release
            )
            self.listener.start()
            
            self.logger.info("Keylogger started")
        
        except Exception as e:
            self.logger.error(f"Failed to start keylogger: {str(e)}")
            self.running = False
    
    def stop(self):
        """Stop keylogger"""
        self.running = False
        
        if self.listener:
            self.listener.stop()
            self.listener = None
        
        # Flush any remaining keystrokes
        self._flush_buffer()
        
        self.logger.info("Keylogger stopped")
    
    def pause(self):
        """Pause keylogger"""
        self.paused = True
        self.logger.info("Keylogger paused")
    
    def resume(self):
        """Resume keylogger"""
        self.paused = False
        self.logger.info("Keylogger resumed")
    
    def update_settings(self, enabled=None):
        """Update keylogger settings"""
        if enabled is not None:
            old_enabled = self.enabled
            self.enabled = enabled
            
            # Start/stop based on new setting
            if self.enabled and not old_enabled:
                self.start()
            elif not self.enabled and old_enabled:
                self.stop()
        
        self.logger.debug(f"Settings updated: Enabled={self.enabled}")
    
    def _on_key_press(self, key):
        """Handle key press event"""
        if not self.running or self.paused:
            return
        
        try:
            # Convert key to string representation
            key_str = self._key_to_string(key)
            
            if key_str:
                # Append to buffer with timestamp
                with self.buffer_lock:
                    self.buffer.append({
                        "key": key_str,
                        "event": "press",
                        "timestamp": datetime.now().isoformat()
                    })
        
        except Exception as e:
            self.logger.error(f"Error handling key press: {str(e)}")
    
    def _on_key_release(self, key):
        """Handle key release event"""
        if not self.running or self.paused:
            return
            
        # We only record key presses, not releases
        # This is just here for the future if we want to expand functionality
        pass
    
    def _key_to_string(self, key):
        """Convert a key event to a string representation"""
        try:
            # Handle special keys
            if key in self.special_keys:
                return self.special_keys[key]
            
            # Handle regular character keys
            if hasattr(key, 'char'):
                return key.char
            
            # Fallback for unknown keys
            return f"\\x{str(key)}"
        
        except Exception as e:
            self.logger.error(f"Error converting key: {str(e)}")
            return None
    
    def _buffer_flush_loop(self):
        """Background thread to periodically flush the keystroke buffer"""
        while True:
            try:
                # Check if it's time to flush (every 5 seconds)
                current_time = time.time()
                if current_time - self.last_flush_time >= 5.0:
                    self._flush_buffer()
                    self.last_flush_time = current_time
            
            except Exception as e:
                self.logger.error(f"Error in buffer flush loop: {str(e)}")
            
            # Sleep for a short time
            time.sleep(1.0)
    
    def _flush_buffer(self):
        """Flush the keystroke buffer to the data queue"""
        with self.buffer_lock:
            # Skip if buffer is empty
            if not self.buffer:
                return
            
            try:
                # Create keystroke data record
                keystroke_data = {
                    "type": "keystrokes",
                    "timestamp": datetime.now().isoformat(),
                    "keystrokes": self.buffer.copy(),
                    "machine_id": os.environ.get("INTEGRITY_MACHINE_ID", "unknown")
                }
                
                # Add to data queue
                self.data_queue.put(keystroke_data)
                
                # Clear buffer
                self.buffer.clear()
                
            except Exception as e:
                self.logger.error(f"Error flushing keystroke buffer: {str(e)}")

#########################################
# DATA MANAGER
#########################################

class DataManager:
    """Manages local data storage and retrieval"""
    
    def __init__(self, data_dir, screenshots_dir, retention_days=7):
        """Initialize the data manager"""
        self.logger = logging.getLogger("integrity.data_manager")
        self.data_dir = data_dir
        self.screenshots_dir = screenshots_dir
        self.retention_days = retention_days
        
        # Ensure directories exist
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.screenshots_dir, exist_ok=True)
        
        # Directory for pending data (retry queue)
        self.pending_dir = os.path.join(self.data_dir, "pending")
        os.makedirs(self.pending_dir, exist_ok=True)
        
        # Lock for file operations
        self.file_lock = threading.Lock()
        
        self.logger.info(f"Data manager initialized with retention period of {retention_days} days")
    
    def store_pending_data(self, data):
        """Store data that failed to send to server for later retry"""
        try:
            with self.file_lock:
                # Generate unique filename
                filename = f"pending_{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}.json"
                filepath = os.path.join(self.pending_dir, filename)
                
                # Write data to file
                with open(filepath, 'w') as f:
                    json.dump(data, f)
                
                self.logger.debug(f"Stored pending data: {filepath}")
                
                return True
        
        except Exception as e:
            self.logger.error(f"Error storing pending data: {str(e)}")
            return False
    
    def get_pending_data(self, limit=5):
        """Get pending data files for retry, limited to specified count"""
        try:
            with self.file_lock:
                # List pending data files sorted by creation time (oldest first)
                files = glob.glob(os.path.join(self.pending_dir, "pending_*.json"))
                files.sort(key=os.path.getctime)
                
                # Limit number of files
                files = files[:limit]
                
                result = []
                for filepath in files:
                    try:
                        with open(filepath, 'r') as f:
                            data = json.load(f)
                            result.append(data)
                    except Exception as e:
                        self.logger.error(f"Error reading pending data file {filepath}: {str(e)}")
                        # Remove corrupted file
                        os.remove(filepath)
                
                return result
        
        except Exception as e:
            self.logger.error(f"Error getting pending data: {str(e)}")
            return []
    
    def remove_pending_data(self, data):
        """Remove a pending data file after successful send"""
        try:
            with self.file_lock:
                # Find the file containing this data
                files = glob.glob(os.path.join(self.pending_dir, "pending_*.json"))
                
                for filepath in files:
                    try:
                        with open(filepath, 'r') as f:
                            file_data = json.load(f)
                            
                            # Compare data (simple comparison for now)
                            if file_data == data:
                                os.remove(filepath)
                                self.logger.debug(f"Removed pending data file: {filepath}")
                                return True
                    except:
                        continue
                
                return False
        
        except Exception as e:
            self.logger.error(f"Error removing pending data: {str(e)}")
            return False
    
    def cleanup_old_data(self):
        """Delete data older than retention period"""
        try:
            self.logger.info(f"Running data cleanup for files older than {self.retention_days} days")
            
            # Calculate cutoff date
            cutoff_date = datetime.now() - timedelta(days=self.retention_days)
            cutoff_timestamp = cutoff_date.timestamp()
            
            with self.file_lock:
                # Clean up screenshots
                self._cleanup_directory(self.screenshots_dir, cutoff_timestamp)
                
                # Clean up pending data
                self._cleanup_directory(self.pending_dir, cutoff_timestamp)
                
                # Clean up any other data files
                self._cleanup_directory(self.data_dir, cutoff_timestamp, exclude=["pending"])
            
            self.logger.info("Data cleanup completed")
            
            return True
        
        except Exception as e:
            self.logger.error(f"Error during data cleanup: {str(e)}")
            self.logger.error(traceback.format_exc())
            return False
    
    def _cleanup_directory(self, directory, cutoff_timestamp, exclude=None):
        """Clean up files in a directory older than the cutoff date"""
        if not os.path.exists(directory):
            return
            
        # Get all files in the directory
        files = os.listdir(directory)
        
        for filename in files:
            # Skip directories in exclude list
            if exclude and filename in exclude:
                continue
                
            filepath = os.path.join(directory, filename)
            
            # Skip directories
            if os.path.isdir(filepath):
                continue
            
            # Check file modification time
            file_mtime = os.path.getmtime(filepath)
            
            if file_mtime < cutoff_timestamp:
                try:
                    os.remove(filepath)
                    self.logger.debug(f"Deleted old file: {filepath}")
                except Exception as e:
                    self.logger.error(f"Error deleting file {filepath}: {str(e)}")
    
    def clear_all_data(self):
        """Clear all local data"""
        try:
            with self.file_lock:
                # Clear screenshots directory
                self._clear_directory(self.screenshots_dir)
                
                # Clear pending data directory
                self._clear_directory(self.pending_dir)
                
                # Clear data directory (excluding pending subdirectory)
                self._clear_directory(self.data_dir, exclude=["pending"])
            
            self.logger.info("All local data cleared")
            
            return True
        
        except Exception as e:
            self.logger.error(f"Error clearing all data: {str(e)}")
            return False
    
    def _clear_directory(self, directory, exclude=None):
        """Clear all files in a directory"""
        if not os.path.exists(directory):
            return
            
        # Get all files in the directory
        files = os.listdir(directory)
        
        for filename in files:
            # Skip directories in exclude list
            if exclude and filename in exclude:
                continue
                
            filepath = os.path.join(directory, filename)
            
            # Skip directories
            if os.path.isdir(filepath):
                continue
            
            try:
                os.remove(filepath)
                self.logger.debug(f"Deleted file: {filepath}")
            except Exception as e:
                self.logger.error(f"Error deleting file {filepath}: {str(e)}")
    
    def get_statistics(self):
        """Get statistics about stored data"""
        try:
            stats = {
                "storage": self._calculate_storage_stats(),
                "active_time": self._estimate_active_time(),
                "top_apps": self._get_top_applications()
            }
            
            return stats
        
        except Exception as e:
            self.logger.error(f"Error getting statistics: {str(e)}")
            return {}
    
    def _calculate_storage_stats(self):
        """Calculate storage statistics"""
        stats = {
            "screenshots_count": 0,
            "screenshots_size": "0 MB",
            "data_count": 0,
            "data_size": "0 MB",
            "total_size": "0 MB"
        }
        
        try:
            # Calculate screenshots stats
            screenshots_size = 0
            screenshots_count = 0
            
            for filename in os.listdir(self.screenshots_dir):
                filepath = os.path.join(self.screenshots_dir, filename)
                if os.path.isfile(filepath):
                    screenshots_size += os.path.getsize(filepath)
                    screenshots_count += 1
            
            # Calculate data stats
            data_size = 0
            data_count = 0
            
            for filename in os.listdir(self.data_dir):
                filepath = os.path.join(self.data_dir, filename)
                if os.path.isfile(filepath):
                    data_size += os.path.getsize(filepath)
                    data_count += 1
            
            # Add pending data
            for filename in os.listdir(self.pending_dir):
                filepath = os.path.join(self.pending_dir, filename)
                if os.path.isfile(filepath):
                    data_size += os.path.getsize(filepath)
                    data_count += 1
            
            # Convert bytes to MB
            screenshots_size_mb = screenshots_size / (1024 * 1024)
            data_size_mb = data_size / (1024 * 1024)
            total_size_mb = screenshots_size_mb + data_size_mb
            
            stats = {
                "screenshots_count": screenshots_count,
                "screenshots_size": f"{screenshots_size_mb:.2f} MB",
                "data_count": data_count,
                "data_size": f"{data_size_mb:.2f} MB",
                "total_size": f"{total_size_mb:.2f} MB"
            }
            
            return stats
        
        except Exception as e:
            self.logger.error(f"Error calculating storage stats: {str(e)}")
            return stats
    
    def _estimate_active_time(self):
        """Estimate active time based on stored data"""
        # This is a placeholder implementation
        # In a real application, you would analyze the actual activity data
        
        active_time = {
            "today": "0h 0m",
            "week": "0h 0m"
        }
        
        try:
            # Get current date
            today = datetime.now().date()
            
            # Calculate activity for today
            today_minutes = self._count_activity_minutes(today)
            today_hours = today_minutes // 60
            today_mins = today_minutes % 60
            active_time["today"] = f"{today_hours}h {today_mins}m"
            
            # Calculate activity for this week
            week_minutes = today_minutes
            
            # Add previous days in the week
            for i in range(1, 7):  # Look back up to 6 days
                day = today - timedelta(days=i)
                week_minutes += self._count_activity_minutes(day)
            
            week_hours = week_minutes // 60
            week_mins = week_minutes % 60
            active_time["week"] = f"{week_hours}h {week_mins}m"
            
            return active_time
        
        except Exception as e:
            self.logger.error(f"Error estimating active time: {str(e)}")
            return active_time
    
    def _count_activity_minutes(self, date):
        """Count activity minutes for a specific date based on screenshots"""
        try:
            # Date string format in screenshot filenames
            date_str = date.strftime("%Y-%m-%d")
            
            # Count screenshots for this date
            screenshot_count = 0
            
            for filename in os.listdir(self.screenshots_dir):
                if filename.startswith("screenshot_") and date_str in filename:
                    screenshot_count += 1
            
            # Each screenshot represents one minute of activity
            return screenshot_count
        
        except Exception as e:
            self.logger.error(f"Error counting activity minutes: {str(e)}")
            return 0
    
    def _get_top_applications(self):
        """Get top applications by usage time"""
        # This is a placeholder implementation
        # In a real application, you would analyze the actual activity data
        
        try:
            # Sample data - in a real app this would be generated from actual usage
            apps = {
                "Browser": "2h 45m",
                "Code Editor": "1h 30m",
                "Email Client": "45m",
                "Terminal": "35m",
                "File Explorer": "20m"
            }
            
            return apps
        
        except Exception as e:
            self.logger.error(f"Error getting top applications: {str(e)}")
            return {}
    
    def update_settings(self, retention_days=None):
        """Update data manager settings"""
        if retention_days is not None:
            self.retention_days = retention_days
            self.logger.debug(f"Retention period updated: {self.retention_days} days")

#########################################
# GUI
#########################################

class IntegrityGUI:
    """Main GUI class for Integrity Assistant"""
    
    def __init__(self, config, auth, server_comms, screenshot_manager, keylogger, data_manager):
        """Initialize the GUI with required components"""
        self.logger = logging.getLogger("integrity.gui")
        self.config = config
        self.auth = auth
        self.server_comms = server_comms
        self.screenshot_manager = screenshot_manager
        self.keylogger = keylogger
        self.data_manager = data_manager
        
        self.root = None
        self.chat_messages = []
        self.privacy_mode = False
        self.system_tray = None
        
        # Theme settings
        if self.config.get("theme") == "light":
            ctk.set_appearance_mode("Light")
        else:
            ctk.set_appearance_mode("Dark")
    
    def start(self):
        """Start the GUI"""
        self.logger.info("Starting Integrity Assistant GUI")
        
        # Create the main window
        self.root = ctk.CTk()
        self.root.title(f"Integrity Assistant {self.config.get('app_version')} - {self.config.get('app_status')}")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Set up the icon
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icon.png")
        if os.path.exists(icon_path):
            if platform.system() == "Windows":
                icon_path_ico = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icon.ico")
                if os.path.exists(icon_path_ico):
                    self.root.iconbitmap(icon_path_ico)
            else:
                try:
                    icon = PhotoImage(file=icon_path)
                    self.root.iconphoto(True, icon)
                except:
                    pass
        
        # Set up system tray if supported
        if self.config.get("minimize_to_tray") and platform.system() == "Windows":
            self._setup_system_tray()
        
        # Set up close handler
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        
        # Create the GUI components
        self._create_gui_components()
        
        # Check authentication status
        if not self.auth.is_authenticated():
            self._show_login()
        else:
            self._update_user_info()
        
        # Start the main loop
        self.root.mainloop()
    
    def stop(self):
        """Stop the GUI"""
        if self.root:
            self.root.quit()
    
    def _setup_system_tray(self):
        """Set up system tray icon and menu if supported"""
        try:
            # This is Windows-specific
            from pystray import MenuItem as item
            from pystray import Icon as icon
            from PIL import Image
            
            # Create an icon for the system tray
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icon.png")
            if os.path.exists(icon_path):
                tray_icon = Image.open(icon_path)
                
                def on_quit_clicked(icon, item):
                    icon.stop()
                    self.stop()
                
                def on_show_clicked(icon, item):
                    self.root.deiconify()
                
                # Create the menu
                menu = (
                    item('Show Integrity Assistant', on_show_clicked),
                    item('Quit', on_quit_clicked)
                )
                
                # Create the icon
                self.system_tray = icon('Integrity', tray_icon, 'Integrity Assistant', menu)
                
                # Run the icon in a separate thread
                threading.Thread(target=self.system_tray.run, daemon=True).start()
                
                self.logger.debug("System tray icon initialized")
            
        except ImportError:
            self.logger.warning("System tray functionality not available (missing pystray package)")
        except Exception as e:
            self.logger.error(f"Failed to initialize system tray: {str(e)}")
    
    def _on_close(self):
        """Handle window close event"""
        if self.config.get("minimize_to_tray") and self.system_tray:
            # Minimize to tray instead of closing
            self.root.withdraw()
        else:
            # Quit the application
            if messagebox.askyesno("Exit", "Are you sure you want to quit Integrity Assistant?"):
                if self.system_tray:
                    self.system_tray.stop()
                self.stop()
    
    def _create_gui_components(self):
        """Create all GUI components"""
        # Main container frame with two columns
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Configure grid
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=3)
        self.main_frame.grid_rowconfigure(0, weight=1)
        
        # Left sidebar
        self.sidebar = ctk.CTkFrame(self.main_frame, width=250)
        self.sidebar.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        # Configure sidebar grid
        self.sidebar.grid_columnconfigure(0, weight=1)
        
        # Logo and title
        self.logo_label = ctk.CTkLabel(
            self.sidebar, 
            text="INTEGRITY",
            font=ctk.CTkFont(family="IBM Plex Mono", size=24, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        self.subtitle_label = ctk.CTkLabel(
            self.sidebar, 
            text="Digital Activity Assistant",
            font=ctk.CTkFont(family="IBM Plex Mono", size=12)
        )
        self.subtitle_label.grid(row=1, column=0, padx=20, pady=(0, 20))
        
        # Status indicator (online/offline)
        self.status_frame = ctk.CTkFrame(self.sidebar, corner_radius=10)
        self.status_frame.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        
        self.status_indicator = ctk.CTkLabel(
            self.status_frame,
            text="●",
            font=ctk.CTkFont(size=16),
            text_color="#00D4A0"  # Turquoise color
        )
        self.status_indicator.grid(row=0, column=0, padx=10)
        
        self.status_label = ctk.CTkLabel(
            self.status_frame,
            text="Online",
            font=ctk.CTkFont(family="IBM Plex Mono", size=12)
        )
        self.status_label.grid(row=0, column=1, padx=10)
        
        # User info
        self.user_frame = ctk.CTkFrame(self.sidebar, corner_radius=10)
        self.user_frame.grid(row=3, column=0, padx=20, pady=10, sticky="ew")
        
        self.user_label = ctk.CTkLabel(
            self.user_frame,
            text="User:",
            font=ctk.CTkFont(family="IBM Plex Mono", size=12, weight="bold")
        )
        self.user_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        
        self.user_value = ctk.CTkLabel(
            self.user_frame,
            text="Not logged in",
            font=ctk.CTkFont(family="IBM Plex Mono", size=12)
        )
        self.user_value.grid(row=0, column=1, padx=10, pady=5, sticky="e")
        
        self.email_label = ctk.CTkLabel(
            self.user_frame,
            text="Email:",
            font=ctk.CTkFont(family="IBM Plex Mono", size=12, weight="bold")
        )
        self.email_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        
        self.email_value = ctk.CTkLabel(
            self.user_frame,
            text="N/A",
            font=ctk.CTkFont(family="IBM Plex Mono", size=12)
        )
        self.email_value.grid(row=1, column=1, padx=10, pady=5, sticky="e")
        
        # Privacy mode toggle
        self.privacy_frame = ctk.CTkFrame(self.sidebar, corner_radius=10)
        self.privacy_frame.grid(row=4, column=0, padx=20, pady=10, sticky="ew")
        
        self.privacy_label = ctk.CTkLabel(
            self.privacy_frame,
            text="Privacy Mode:",
            font=ctk.CTkFont(family="IBM Plex Mono", size=12, weight="bold")
        )
        self.privacy_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        self.privacy_switch = ctk.CTkSwitch(
            self.privacy_frame,
            text="",
            command=self._toggle_privacy_mode
        )
        self.privacy_switch.grid(row=0, column=1, padx=10, pady=10, sticky="e")
        
        # Sidebar buttons
        self.dashboard_btn = ctk.CTkButton(
            self.sidebar,
            text="Dashboard",
            font=ctk.CTkFont(family="IBM Plex Mono"),
            command=self._show_dashboard
        )
        self.dashboard_btn.grid(row=5, column=0, padx=20, pady=10, sticky="ew")
        
        self.settings_btn = ctk.CTkButton(
            self.sidebar,
            text="Settings",
            font=ctk.CTkFont(family="IBM Plex Mono"),
            command=self._show_settings
        )
        self.settings_btn.grid(row=6, column=0, padx=20, pady=10, sticky="ew")
        
        self.stats_btn = ctk.CTkButton(
            self.sidebar,
            text="Activity Stats",
            font=ctk.CTkFont(family="IBM Plex Mono"),
            command=self._show_statistics
        )
        self.stats_btn.grid(row=7, column=0, padx=20, pady=10, sticky="ew")
        
        self.help_btn = ctk.CTkButton(
            self.sidebar,
            text="Help",
            font=ctk.CTkFont(family="IBM Plex Mono"),
            command=self._show_help
        )
        self.help_btn.grid(row=8, column=0, padx=20, pady=10, sticky="ew")
        
        # Spacer
        self.sidebar.grid_rowconfigure(9, weight=1)
        
        # Version info
        self.version_label = ctk.CTkLabel(
            self.sidebar,
            text=f"v{self.config.get('app_version')} {self.config.get('app_status')}",
            font=ctk.CTkFont(family="IBM Plex Mono", size=10)
        )
        self.version_label.grid(row=10, column=0, padx=20, pady=10)
        
        # Main content area
        self.content_frame = ctk.CTkFrame(self.main_frame)
        self.content_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        
        # Initially show dashboard
        self._show_dashboard()
        
        # Start status update thread
        self.status_thread = threading.Thread(target=self._update_status_loop, daemon=True)
        self.status_thread.start()
    
    def _show_dashboard(self):
        """Show the dashboard/chat view"""
        # Clear content frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Configure content grid
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=0)  # Title
        self.content_frame.grid_rowconfigure(1, weight=1)  # Chat area
        self.content_frame.grid_rowconfigure(2, weight=0)  # Input area
        
        # Dashboard title
        title_frame = ctk.CTkFrame(self.content_frame)
        title_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        
        dashboard_title = ctk.CTkLabel(
            title_frame,
            text="Integrity Assistant Dashboard",
            font=ctk.CTkFont(family="IBM Plex Mono", size=18, weight="bold")
        )
        dashboard_title.pack(pady=10)
        
        # Chat area
        chat_frame = ctk.CTkFrame(self.content_frame)
        chat_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        
        # Messages area with scrollbar
        self.messages_frame = ctk.CTkScrollableFrame(chat_frame)
        self.messages_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Display existing messages if any
        self._display_chat_messages()
        
        # Input area
        input_frame = ctk.CTkFrame(self.content_frame)
        input_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        
        input_frame.grid_columnconfigure(0, weight=1)
        input_frame.grid_columnconfigure(1, weight=0)
        
        # Message input
        self.message_input = ctk.CTkTextbox(
            input_frame,
            height=80,
            font=ctk.CTkFont(family="IBM Plex Mono", size=12)
        )
        self.message_input.grid(row=0, column=0, padx=(10, 5), pady=10, sticky="ew")
        self.message_input.bind("<Return>", self._on_message_enter)
        
        # Send button
        send_button = ctk.CTkButton(
            input_frame,
            text="Send",
            width=100,
            font=ctk.CTkFont(family="IBM Plex Mono"),
            command=self._send_message
        )
        send_button.grid(row=0, column=1, padx=(5, 10), pady=10)
        
        # If no messages, show welcome message
        if not self.chat_messages:
            self._add_assistant_message(
                "Welcome to Integrity Assistant! I'm monitoring your digital activity to help you "
                "find information and understand your work patterns. Ask me anything about your "
                "digital activity, like 'What was I working on yesterday?' or 'Find the document "
                "I was editing this morning.'"
            )
    
    def _show_settings(self):
        """Show the settings view"""
        # Clear content frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Configure content grid
        self.content_frame.grid_columnconfigure(0, weight=1)
        
        # Settings title
        title_frame = ctk.CTkFrame(self.content_frame)
        title_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        
        settings_title = ctk.CTkLabel(
            title_frame,
            text="Settings",
            font=ctk.CTkFont(family="IBM Plex Mono", size=18, weight="bold")
        )
        settings_title.pack(pady=10)
        
        # Settings content in a scrollable frame
        settings_scroll = ctk.CTkScrollableFrame(self.content_frame)
        settings_scroll.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        
        # General Settings Section
        general_frame = ctk.CTkFrame(settings_scroll)
        general_frame.pack(fill="x", padx=10, pady=10)
        
        general_label = ctk.CTkLabel(
            general_frame,
            text="General Settings",
            font=ctk.CTkFont(family="IBM Plex Mono", size=16, weight="bold")
        )
        general_label.grid(row=0, column=0, padx=10, pady=10, sticky="w", columnspan=2)
        
        # Theme setting
        theme_label = ctk.CTkLabel(
            general_frame,
            text="Theme:",
            font=ctk.CTkFont(family="IBM Plex Mono")
        )
        theme_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        
        theme_var = ctk.StringVar(value=self.config.get("theme"))
        theme_options = ctk.CTkOptionMenu(
            general_frame,
            values=["dark", "light"],
            variable=theme_var,
            command=self._change_theme
        )
        theme_options.grid(row=1, column=1, padx=10, pady=10, sticky="e")
        
        # Startup setting
        startup_label = ctk.CTkLabel(
            general_frame,
            text="Run at Startup:",
            font=ctk.CTkFont(family="IBM Plex Mono")
        )
        startup_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")
        
        startup_var = ctk.BooleanVar(value=self.config.get("startup"))
        startup_switch = ctk.CTkSwitch(
            general_frame,
            text="",
            variable=startup_var,
            command=lambda: self._save_setting("startup", startup_var.get())
        )
        startup_switch.grid(row=2, column=1, padx=10, pady=10, sticky="e")
        
        # Minimize to tray setting
        tray_label = ctk.CTkLabel(
            general_frame,
            text="Minimize to Tray:",
            font=ctk.CTkFont(family="IBM Plex Mono")
        )
        tray_label.grid(row=3, column=0, padx=10, pady=10, sticky="w")
        
        tray_var = ctk.BooleanVar(value=self.config.get("minimize_to_tray"))
        tray_switch = ctk.CTkSwitch(
            general_frame,
            text="",
            variable=tray_var,
            command=lambda: self._save_setting("minimize_to_tray", tray_var.get())
        )
        tray_switch.grid(row=3, column=1, padx=10, pady=10, sticky="e")
        
        # Monitoring Settings Section
        monitoring_frame = ctk.CTkFrame(settings_scroll)
        monitoring_frame.pack(fill="x", padx=10, pady=10)
        
        monitoring_label = ctk.CTkLabel(
            monitoring_frame,
            text="Monitoring Settings",
            font=ctk.CTkFont(family="IBM Plex Mono", size=16, weight="bold")
        )
        monitoring_label.grid(row=0, column=0, padx=10, pady=10, sticky="w", columnspan=2)
        
        # OCR setting
        ocr_label = ctk.CTkLabel(
            monitoring_frame,
            text="Enable OCR Text Extraction:",
            font=ctk.CTkFont(family="IBM Plex Mono")
        )
        ocr_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        
        ocr_var = ctk.BooleanVar(value=self.config.get("ocr_enabled"))
        ocr_switch = ctk.CTkSwitch(
            monitoring_frame,
            text="",
            variable=ocr_var,
            command=lambda: self._save_setting("ocr_enabled", ocr_var.get())
        )
        ocr_switch.grid(row=1, column=1, padx=10, pady=10, sticky="e")
        
        # Keylogger setting
        keylogger_label = ctk.CTkLabel(
            monitoring_frame,
            text="Enable Keystroke Logging:",
            font=ctk.CTkFont(family="IBM Plex Mono")
        )
        keylogger_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")
        
        keylogger_var = ctk.BooleanVar(value=self.config.get("keylogger_enabled"))
        keylogger_switch = ctk.CTkSwitch(
            monitoring_frame,
            text="",
            variable=keylogger_var,
            command=lambda: self._save_setting("keylogger_enabled", keylogger_var.get())
        )
        keylogger_switch.grid(row=2, column=1, padx=10, pady=10, sticky="e")
        
        # Monitor all screens setting
        monitors_label = ctk.CTkLabel(
            monitoring_frame,
            text="Monitor All Screens:",
            font=ctk.CTkFont(family="IBM Plex Mono")
        )
        monitors_label.grid(row=3, column=0, padx=10, pady=10, sticky="w")
        
        monitors_var = ctk.BooleanVar(value=self.config.get("monitor_all"))
        monitors_switch = ctk.CTkSwitch(
            monitoring_frame,
            text="",
            variable=monitors_var,
            command=lambda: self._save_setting("monitor_all", monitors_var.get())
        )
        monitors_switch.grid(row=3, column=1, padx=10, pady=10, sticky="e")
        
        # Store screenshots setting
        screenshots_label = ctk.CTkLabel(
            monitoring_frame,
            text="Store Screenshots:",
            font=ctk.CTkFont(family="IBM Plex Mono")
        )
        screenshots_label.grid(row=4, column=0, padx=10, pady=10, sticky="w")
        
        screenshots_var = ctk.BooleanVar(value=self.config.get("store_screenshots"))
        screenshots_switch = ctk.CTkSwitch(
            monitoring_frame,
            text="",
            variable=screenshots_var,
            command=lambda: self._save_setting("store_screenshots", screenshots_var.get())
        )
        screenshots_switch.grid(row=4, column=1, padx=10, pady=10, sticky="e")
        
        # Data Retention Frame
        retention_frame = ctk.CTkFrame(settings_scroll)
        retention_frame.pack(fill="x", padx=10, pady=10)
        
        retention_label = ctk.CTkLabel(
            retention_frame,
            text="Data Retention",
            font=ctk.CTkFont(family="IBM Plex Mono", size=16, weight="bold")
        )
        retention_label.grid(row=0, column=0, padx=10, pady=10, sticky="w", columnspan=2)
        
        # Retention days setting
        days_label = ctk.CTkLabel(
            retention_frame,
            text="Keep Local Data For (days):",
            font=ctk.CTkFont(family="IBM Plex Mono")
        )
        days_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        
        days_var = ctk.IntVar(value=self.config.get("retention_days"))
        days_slider = ctk.CTkSlider(
            retention_frame,
            from_=1,
            to=30,
            number_of_steps=29,
            variable=days_var,
            command=lambda value: self._update_days_label(value)
        )
        days_slider.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        
        self.days_value_label = ctk.CTkLabel(
            retention_frame,
            text=f"{days_var.get()} days",
            font=ctk.CTkFont(family="IBM Plex Mono")
        )
        self.days_value_label.grid(row=1, column=2, padx=10, pady=10)
        
        # Clear Data Button
        clear_data_btn = ctk.CTkButton(
            retention_frame,
            text="Clear All Local Data",
            font=ctk.CTkFont(family="IBM Plex Mono"),
            fg_color="#E74C3C",  # Red color
            hover_color="#C0392B",
            command=self._clear_all_data
        )
        clear_data_btn.grid(row=2, column=0, padx=10, pady=20, sticky="w", columnspan=3)
        
        # Account Section
        account_frame = ctk.CTkFrame(settings_scroll)
        account_frame.pack(fill="x", padx=10, pady=10)
        
        account_label = ctk.CTkLabel(
            account_frame,
            text="Account",
            font=ctk.CTkFont(family="IBM Plex Mono", size=16, weight="bold")
        )
        account_label.grid(row=0, column=0, padx=10, pady=10, sticky="w", columnspan=2)
        
        # Logout Button
        logout_btn = ctk.CTkButton(
            account_frame,
            text="Logout",
            font=ctk.CTkFont(family="IBM Plex Mono"),
            command=self._logout_user
        )
        logout_btn.grid(row=1, column=0, padx=10, pady=20, sticky="w")
        
        # Save settings button at the bottom
        save_frame = ctk.CTkFrame(self.content_frame)
        save_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        
        save_btn = ctk.CTkButton(
            save_frame,
            text="Save All Settings",
            font=ctk.CTkFont(family="IBM Plex Mono", weight="bold"),
            command=self._save_all_settings
        )
        save_btn.pack(pady=10)
    
    def _update_days_label(self, value):
        """Update the days value label when slider changes"""
        days = int(value)
        self.days_value_label.configure(text=f"{days} days")
        self._save_setting("retention_days", days)
    
    def _save_setting(self, key, value):
        """Save a single setting to the config"""
        self.config.set(key, value)
        self.logger.debug(f"Setting {key} saved: {value}")
    
    def _save_all_settings(self):
        """Save all settings and apply changes"""
        # Settings are saved as they're changed, just show confirmation
        messagebox.showinfo("Settings Saved", "All settings have been saved and applied.")
        
        # Apply any settings that need immediate effect
        if self.config.get("theme") == "light":
            ctk.set_appearance_mode("Light")
        else:
            ctk.set_appearance_mode("Dark")
            
        # Update other components based on settings
        self.screenshot_manager.update_settings(
            ocr_enabled=self.config.get("ocr_enabled"),
            monitor_all=self.config.get("monitor_all"),
            store_screenshots=self.config.get("store_screenshots")
        )
        
        self.keylogger.update_settings(
            enabled=self.config.get("keylogger_enabled")
        )
        
        self.data_manager.update_settings(
            retention_days=self.config.get("retention_days")
        )
    
    def _clear_all_data(self):
        """Clear all local data after confirmation"""
        if messagebox.askyesno(
            "Clear Data", 
            "Are you sure you want to delete ALL local data? This cannot be undone."
        ):
            # Call data manager to clear all data
            self.data_manager.clear_all_data()
            messagebox.showinfo("Data Cleared", "All local data has been deleted.")
    
    def _change_theme(self, theme):
        """Change the application theme"""
        self.config.set("theme", theme)
        
        if theme == "light":
            ctk.set_appearance_mode("Light")
        else:
            ctk.set_appearance_mode("Dark")
    
    def _toggle_privacy_mode(self):
        """Toggle privacy mode on/off"""
        self.privacy_mode = self.privacy_switch.get()
        
        if self.privacy_mode:
            self.status_indicator.configure(text_color="#E74C3C")  # Red
            self.status_label.configure(text="Privacy Mode")
            
            # Pause monitoring
            self.screenshot_manager.pause()
            self.keylogger.pause()
            
            # Log to user
            self._add_assistant_message("Privacy mode enabled. All monitoring is paused.")
        else:
            self.status_indicator.configure(text_color="#00D4A0")  # Turquoise
            self.status_label.configure(text="Online")
            
            # Resume monitoring
            self.screenshot_manager.resume()
            self.keylogger.resume()
            
            # Log to user
            self._add_assistant_message("Privacy mode disabled. Monitoring resumed.")
    
    def _show_statistics(self):
        """Show activity statistics view"""
        # Clear content frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Configure content grid
        self.content_frame.grid_columnconfigure(0, weight=1)
        
        # Statistics title
        title_frame = ctk.CTkFrame(self.content_frame)
        title_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        
        stats_title = ctk.CTkLabel(
            title_frame,
            text="Activity Statistics",
            font=ctk.CTkFont(family="IBM Plex Mono", size=18, weight="bold")
        )
        stats_title.pack(pady=10)
        
        # Statistics content in a scrollable frame
        stats_scroll = ctk.CTkScrollableFrame(self.content_frame)
        stats_scroll.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        
        # Get statistics from data manager
        stats = self.data_manager.get_statistics()
        
        # Display statistics
        summary_frame = ctk.CTkFrame(stats_scroll)
        summary_frame.pack(fill="x", padx=10, pady=10)
        
        summary_label = ctk.CTkLabel(
            summary_frame,
            text="Activity Summary",
            font=ctk.CTkFont(family="IBM Plex Mono", size=16, weight="bold")
        )
        summary_label.pack(pady=10)
        
        # If no data available
        if not stats or not stats.get("active_time"):
            no_data_label = ctk.CTkLabel(
                summary_frame,
                text="No activity data available yet. Continue using your computer normally,\nand statistics will appear here as data is collected.",
                font=ctk.CTkFont(family="IBM Plex Mono")
            )
            no_data_label.pack(pady=20)
        else:
            # Activity time today
            today_frame = ctk.CTkFrame(summary_frame)
            today_frame.pack(fill="x", padx=20, pady=10)
            
            today_label = ctk.CTkLabel(
                today_frame,
                text="Today's Activity:",
                font=ctk.CTkFont(family="IBM Plex Mono", weight="bold")
            )
            today_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
            
            today_value = ctk.CTkLabel(
                today_frame,
                text=f"{stats.get('active_time', {}).get('today', '0h 0m')}",
                font=ctk.CTkFont(family="IBM Plex Mono")
            )
            today_value.grid(row=0, column=1, padx=10, pady=10, sticky="e")
            
            # Activity time this week
            week_frame = ctk.CTkFrame(summary_frame)
            week_frame.pack(fill="x", padx=20, pady=10)
            
            week_label = ctk.CTkLabel(
                week_frame,
                text="This Week:",
                font=ctk.CTkFont(family="IBM Plex Mono", weight="bold")
            )
            week_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
            
            week_value = ctk.CTkLabel(
                week_frame,
                text=f"{stats.get('active_time', {}).get('week', '0h 0m')}",
                font=ctk.CTkFont(family="IBM Plex Mono")
            )
            week_value.grid(row=0, column=1, padx=10, pady=10, sticky="e")
            
            # Top applications
            top_apps_frame = ctk.CTkFrame(stats_scroll)
            top_apps_frame.pack(fill="x", padx=10, pady=10)
            
            top_apps_label = ctk.CTkLabel(
                top_apps_frame,
                text="Top Applications",
                font=ctk.CTkFont(family="IBM Plex Mono", size=16, weight="bold")
            )
            top_apps_label.pack(pady=10)
            
            if stats.get("top_apps"):
                for i, (app, time_spent) in enumerate(stats.get("top_apps", {}).items()):
                    app_frame = ctk.CTkFrame(top_apps_frame)
                    app_frame.pack(fill="x", padx=20, pady=5)
                    
                    app_label = ctk.CTkLabel(
                        app_frame,
                        text=f"{i+1}. {app}",
                        font=ctk.CTkFont(family="IBM Plex Mono")
                    )
                    app_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
                    
                    time_label = ctk.CTkLabel(
                        app_frame,
                        text=time_spent,
                        font=ctk.CTkFont(family="IBM Plex Mono")
                    )
                    time_label.grid(row=0, column=1, padx=10, pady=5, sticky="e")
            else:
                no_apps_label = ctk.CTkLabel(
                    top_apps_frame,
                    text="No application data available yet.",
                    font=ctk.CTkFont(family="IBM Plex Mono")
                )
                no_apps_label.pack(pady=10)
            
            # Storage statistics
            storage_frame = ctk.CTkFrame(stats_scroll)
            storage_frame.pack(fill="x", padx=10, pady=10)
            
            storage_label = ctk.CTkLabel(
                storage_frame,
                text="Storage Usage",
                font=ctk.CTkFont(family="IBM Plex Mono", size=16, weight="bold")
            )
            storage_label.pack(pady=10)
            
            storage_details = ctk.CTkFrame(storage_frame)
            storage_details.pack(fill="x", padx=20, pady=10)
            
            screenshots_label = ctk.CTkLabel(
                storage_details,
                text="Screenshots:",
                font=ctk.CTkFont(family="IBM Plex Mono")
            )
            screenshots_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
            
            screenshots_value = ctk.CTkLabel(
                storage_details,
                text=f"{stats.get('storage', {}).get('screenshots_count', 0)} files ({stats.get('storage', {}).get('screenshots_size', '0 MB')})",
                font=ctk.CTkFont(family="IBM Plex Mono")
            )
            screenshots_value.grid(row=0, column=1, padx=10, pady=5, sticky="e")
            
            data_label = ctk.CTkLabel(
                storage_details,
                text="Data Files:",
                font=ctk.CTkFont(family="IBM Plex Mono")
            )
            data_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
            
            data_value = ctk.CTkLabel(
                storage_details,
                text=f"{stats.get('storage', {}).get('data_count', 0)} files ({stats.get('storage', {}).get('data_size', '0 MB')})",
                font=ctk.CTkFont(family="IBM Plex Mono")
            )
            data_value.grid(row=1, column=1, padx=10, pady=5, sticky="e")
            
            total_label = ctk.CTkLabel(
                storage_details,
                text="Total Storage:",
                font=ctk.CTkFont(family="IBM Plex Mono", weight="bold")
            )
            total_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
            
            total_value = ctk.CTkLabel(
                storage_details,
                text=f"{stats.get('storage', {}).get('total_size', '0 MB')}",
                font=ctk.CTkFont(family="IBM Plex Mono", weight="bold")
            )
            total_value.grid(row=2, column=1, padx=10, pady=5, sticky="e")
        
        # Refresh button
        refresh_btn = ctk.CTkButton(
            self.content_frame,
            text="Refresh Statistics",
            font=ctk.CTkFont(family="IBM Plex Mono"),
            command=self._show_statistics
        )
        refresh_btn.grid(row=2, column=0, padx=10, pady=10)
    
    def _show_help(self):
        """Show help and documentation view"""
        # Clear content frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Configure content grid
        self.content_frame.grid_columnconfigure(0, weight=1)
        
        # Help title
        title_frame = ctk.CTkFrame(self.content_frame)
        title_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        
        help_title = ctk.CTkLabel(
            title_frame,
            text="Help & Documentation",
            font=ctk.CTkFont(family="IBM Plex Mono", size=18, weight="bold")
        )
        help_title.pack(pady=10)
        
        # Help content in a scrollable frame
        help_scroll = ctk.CTkScrollableFrame(self.content_frame)
        help_scroll.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        
        # About section
        about_frame = ctk.CTkFrame(help_scroll)
        about_frame.pack(fill="x", padx=10, pady=10)
        
        about_label = ctk.CTkLabel(
            about_frame,
            text="About Integrity Assistant",
            font=ctk.CTkFont(family="IBM Plex Mono", size=16, weight="bold")
        )
        about_label.pack(pady=10)
        
        about_text = ctk.CTkLabel(
            about_frame,
            text=(
                "Integrity Assistant is an AI-powered digital activity assistant that helps you "
                "understand and search your computer activity. It monitors your screen and keyboard "
                "input to create a searchable record of your digital life.\n\n"
                f"Version: {self.config.get('app_version')} {self.config.get('app_status')}"
            ),
            font=ctk.CTkFont(family="IBM Plex Mono"),
            wraplength=600,
            justify="left"
        )
        about_text.pack(padx=20, pady=10)
        
        # How it works section
        how_frame = ctk.CTkFrame(help_scroll)
        how_frame.pack(fill="x", padx=10, pady=10)
        
        how_label = ctk.CTkLabel(
            how_frame,
            text="How It Works",
            font=ctk.CTkFont(family="IBM Plex Mono", size=16, weight="bold")
        )
        how_label.pack(pady=10)
        
        how_text = ctk.CTkLabel(
            how_frame,
            text=(
                "Integrity captures screenshots of your screen activity and records keystrokes to understand "
                "what you're working on. This data is processed locally on your computer and then sent "
                "securely to our servers for AI analysis.\n\n"
                "You can ask questions about your digital activity in natural language, and Integrity will "
                "search through your activity data to find answers."
            ),
            font=ctk.CTkFont(family="IBM Plex Mono"),
            wraplength=600,
            justify="left"
        )
        how_text.pack(padx=20, pady=10)
        
        # Privacy section
        privacy_frame = ctk.CTkFrame(help_scroll)
        privacy_frame.pack(fill="x", padx=10, pady=10)
        
        privacy_label = ctk.CTkLabel(
            privacy_frame,
            text="Privacy & Security",
            font=ctk.CTkFont(family="IBM Plex Mono", size=16, weight="bold")
        )
        privacy_label.pack(pady=10)
        
        privacy_text = ctk.CTkLabel(
            privacy_frame,
            text=(
                "Your privacy is our top priority. All data is encrypted using AES-256 encryption both "
                "locally and during transmission. Screenshot data is only stored locally for the duration "
                "specified in your settings (default: 7 days).\n\n"
                "You can enable Privacy Mode at any time to pause all monitoring, and you can exclude "
                "specific applications or websites from being monitored in the settings."
            ),
            font=ctk.CTkFont(family="IBM Plex Mono"),
            wraplength=600,
            justify="left"
        )
        privacy_text.pack(padx=20, pady=10)
        
        # FAQ section
        faq_frame = ctk.CTkFrame(help_scroll)
        faq_frame.pack(fill="x", padx=10, pady=10)
        
        faq_label = ctk.CTkLabel(
            faq_frame,
            text="Frequently Asked Questions",
            font=ctk.CTkFont(family="IBM Plex Mono", size=16, weight="bold")
        )
        faq_label.pack(pady=10)
        
        faqs = [
            ("Is my data secure?", 
             "Yes, all your data is encrypted locally and during transmission using AES-256 encryption."),
            
            ("Can I delete my data?", 
             "Yes, you can clear all local data in Settings, and you can request deletion of your server data by contacting support."),
            
            ("How much disk space does Integrity use?", 
             "Integrity typically uses between 100MB-500MB of disk space, depending on your retention settings and activity level."),
            
            ("Will Integrity slow down my computer?", 
             "Integrity is designed to use minimal resources. It typically uses less than 2% CPU and 100MB of RAM."),
            
            ("Can I use Integrity offline?", 
             "Integrity requires an internet connection to process your queries, but it will continue to collect data offline and sync when reconnected.")
        ]
        
        for i, (question, answer) in enumerate(faqs):
            faq_item = ctk.CTkFrame(faq_frame)
            faq_item.pack(fill="x", padx=20, pady=5)
            
            q_label = ctk.CTkLabel(
                faq_item,
                text=f"Q: {question}",
                font=ctk.CTkFont(family="IBM Plex Mono", weight="bold"),
                anchor="w",
                justify="left"
            )
            q_label.pack(padx=10, pady=(10, 5), anchor="w")
            
            a_label = ctk.CTkLabel(
                faq_item,
                text=f"A: {answer}",
                font=ctk.CTkFont(family="IBM Plex Mono"),
                wraplength=550,
                anchor="w",
                justify="left"
            )
            a_label.pack(padx=10, pady=(0, 10), anchor="w")
        
        # Support section
        support_frame = ctk.CTkFrame(help_scroll)
        support_frame.pack(fill="x", padx=10, pady=10)
        
        support_label = ctk.CTkLabel(
            support_frame,
            text="Support",
            font=ctk.CTkFont(family="IBM Plex Mono", size=16, weight="bold")
        )
        support_label.pack(pady=10)
        
        support_text = ctk.CTkLabel(
            support_frame,
            text="Need help? Contact our support team or visit our documentation website:",
            font=ctk.CTkFont(family="IBM Plex Mono"),
            wraplength=600,
            justify="left"
        )
        support_text.pack(padx=20, pady=10)
        
        buttons_frame = ctk.CTkFrame(support_frame, fg_color="transparent")
        buttons_frame.pack(padx=20, pady=10)
        
        website_btn = ctk.CTkButton(
            buttons_frame,
            text="Visit Website",
            font=ctk.CTkFont(family="IBM Plex Mono"),
            command=lambda: webbrowser.open("https://integrity-assistant.com")
        )
        website_btn.grid(row=0, column=0, padx=10, pady=10)
        
        docs_btn = ctk.CTkButton(
            buttons_frame,
            text="Documentation",
            font=ctk.CTkFont(family="IBM Plex Mono"),
            command=lambda: webbrowser.open("https://integrity-assistant.com/docs")
        )
        docs_btn.grid(row=0, column=1, padx=10, pady=10)
        
        support_btn = ctk.CTkButton(
            buttons_frame,
            text="Contact Support",
            font=ctk.CTkFont(family="IBM Plex Mono"),
            command=lambda: webbrowser.open("mailto:support@integrity-assistant.com")
        )
        support_btn.grid(row=0, column=2, padx=10, pady=10)
    
    def _show_login(self):
        """Show login dialog"""
        login_window = ctk.CTkToplevel(self.root)
        login_window.title("Login to Integrity Assistant")
        login_window.geometry("400x500")
        login_window.resizable(False, False)
        login_window.focus_set()  # Set focus to the login window
        
        # Make it modal
        login_window.grab_set()
        login_window.transient(self.root)
        
        # Center the window
        login_window.update_idletasks()
        width = login_window.winfo_width()
        height = login_window.winfo_height()
        x = (login_window.winfo_screenwidth() // 2) - (width // 2)
        y = (login_window.winfo_screenheight() // 2) - (height // 2)
        login_window.geometry(f"{width}x{height}+{x}+{y}")
        
        # Title
        title_label = ctk.CTkLabel(
            login_window,
            text="Integrity Assistant",
            font=ctk.CTkFont(family="IBM Plex Mono", size=24, weight="bold")
        )
        title_label.pack(pady=(30, 10))
        
        subtitle_label = ctk.CTkLabel(
            login_window,
            text="Sign in to continue",
            font=ctk.CTkFont(family="IBM Plex Mono", size=14)
        )
        subtitle_label.pack(pady=(0, 30))
        
        # Create tabs
        tab_view = ctk.CTkTabview(login_window, width=350)
        tab_view.pack(pady=10, padx=20, fill="both", expand=True)
        
        login_tab = tab_view.add("Login")
        register_tab = tab_view.add("Register")
        
        # Login tab
        email_label = ctk.CTkLabel(
            login_tab,
            text="Email:",
            font=ctk.CTkFont(family="IBM Plex Mono")
        )
        email_label.grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")
        
        email_entry = ctk.CTkEntry(
            login_tab,
            width=250,
            font=ctk.CTkFont(family="IBM Plex Mono")
        )
        email_entry.grid(row=1, column=0, padx=20, pady=5)
        
        password_label = ctk.CTkLabel(
            login_tab,
            text="Password:",
            font=ctk.CTkFont(family="IBM Plex Mono")
        )
        password_label.grid(row=2, column=0, padx=20, pady=(20, 5), sticky="w")
        
        password_entry = ctk.CTkEntry(
            login_tab,
            width=250,
            font=ctk.CTkFont(family="IBM Plex Mono"),
            show="•"
        )
        password_entry.grid(row=3, column=0, padx=20, pady=5)
        
        # Error message label (hidden initially)
        login_error_label = ctk.CTkLabel(
            login_tab,
            text="",
            font=ctk.CTkFont(family="IBM Plex Mono"),
            text_color="#E74C3C"  # Red color
        )
        login_error_label.grid(row=4, column=0, padx=20, pady=10)
        
        login_btn = ctk.CTkButton(
            login_tab,
            text="Login",
            font=ctk.CTkFont(family="IBM Plex Mono"),
            width=250,
            command=lambda: self._login_user(email_entry.get(), password_entry.get(), login_error_label, login_window)
        )
        login_btn.grid(row=5, column=0, padx=20, pady=20)
        
        # Register tab
        reg_name_label = ctk.CTkLabel(
            register_tab,
            text="Full Name:",
            font=ctk.CTkFont(family="IBM Plex Mono")
        )
        reg_name_label.grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")
        
        reg_name_entry = ctk.CTkEntry(
            register_tab,
            width=250,
            font=ctk.CTkFont(family="IBM Plex Mono")
        )
        reg_name_entry.grid(row=1, column=0, padx=20, pady=5)
        
        reg_email_label = ctk.CTkLabel(
            register_tab,
            text="Email:",
            font=ctk.CTkFont(family="IBM Plex Mono")
        )
        reg_email_label.grid(row=2, column=0, padx=20, pady=(20, 5), sticky="w")
        
        reg_email_entry = ctk.CTkEntry(
            register_tab,
            width=250,
            font=ctk.CTkFont(family="IBM Plex Mono")
        )
        reg_email_entry.grid(row=3, column=0, padx=20, pady=5)
        
        reg_password_label = ctk.CTkLabel(
            register_tab,
            text="Password:",
            font=ctk.CTkFont(family="IBM Plex Mono")
        )
        reg_password_label.grid(row=4, column=0, padx=20, pady=(20, 5), sticky="w")
        
        reg_password_entry = ctk.CTkEntry(
            register_tab,
            width=250,
            font=ctk.CTkFont(family="IBM Plex Mono"),
            show="•"
        )
        reg_password_entry.grid(row=5, column=0, padx=20, pady=5)
        
        # Error message label (hidden initially)
        register_error_label = ctk.CTkLabel(
            register_tab,
            text="",
            font=ctk.CTkFont(family="IBM Plex Mono"),
            text_color="#E74C3C"  # Red color
        )
        register_error_label.grid(row=6, column=0, padx=20, pady=10)
        
        register_btn = ctk.CTkButton(
            register_tab,
            text="Create Account",
            font=ctk.CTkFont(family="IBM Plex Mono"),
            width=250,
            command=lambda: self._register_user(
                reg_name_entry.get(),
                reg_email_entry.get(),
                reg_password_entry.get(),
                register_error_label,
                login_window
            )
        )
        register_btn.grid(row=7, column=0, padx=20, pady=20)
        
        # Select login tab by default
        tab_view.set("Login")
        
        # Set focus to email entry
        email_entry.focus_set()
        
        # Bind Enter key to login button
        email_entry.bind("<Return>", lambda event: login_btn.invoke())
        password_entry.bind("<Return>", lambda event: login_btn.invoke())
    
    def _login_user(self, email, password, error_label, login_window):
        """Attempt to log in user"""
        if not email or not password:
            error_label.configure(text="Please enter both email and password")
            return
        
        # Show loading
        error_label.configure(text="Logging in...", text_color="white")
        login_window.update()
        
        # Attempt login
        success, error = self.auth.login(email, password)
        
        if success:
            # Close login window
            login_window.destroy()
            
            # Update user info
            self._update_user_info()
            
            # Show welcome message
            self._add_assistant_message(
                f"Welcome back to Integrity Assistant! I'm monitoring your digital activity "
                f"to help you find information and understand your work patterns."
            )
        else:
            # Show error
            error_label.configure(text=error, text_color="#E74C3C")
    
    def _register_user(self, name, email, password, error_label, login_window):
        """Attempt to register new user"""
        if not name or not email or not password:
            error_label.configure(text="Please fill in all fields")
            return
        
        if len(password) < 8:
            error_label.configure(text="Password must be at least 8 characters")
            return
        
        # Show loading
        error_label.configure(text="Creating account...", text_color="white")
        login_window.update()
        
        # Attempt registration
        success, error = self.auth.register(email, password, name)
        
        if success:
            # Close login window
            login_window.destroy()
            
            # Update user info
            self._update_user_info()
            
            # Show welcome message
            self._add_assistant_message(
                f"Welcome to Integrity Assistant, {name}! I'm monitoring your digital activity "
                f"to help you find information and understand your work patterns. Ask me "
                f"anything about your digital activity to get started."
            )
        else:
            # Show error
            error_label.configure(text=error, text_color="#E74C3C")
    
    def _update_user_info(self):
        """Update the UI with current user info"""
        if self.auth.is_authenticated():
            user_info = self.auth.get_user_info()
            
            if user_info:
                self.user_value.configure(text=user_info.get("name", "User"))
                self.email_value.configure(text=user_info.get("email", ""))
    
    def _logout_user(self):
        """Log out the current user"""
        if messagebox.askyesno("Logout", "Are you sure you want to log out?"):
            success = self.auth.logout()
            
            if success:
                # Update user info
                self.user_value.configure(text="Not logged in")
                self.email_value.configure(text="N/A")
                
                # Show login dialog
                self._show_login()
    
    def _display_chat_messages(self):
        """Display all chat messages in the UI"""
        # Clear existing messages
        for widget in self.messages_frame.winfo_children():
            widget.destroy()
        
        # Add each message
        for message in self.chat_messages:
            message_frame = ctk.CTkFrame(self.messages_frame, corner_radius=10)
            message_frame.pack(fill="x", padx=10, pady=5, anchor="w" if message["sender"] == "assistant" else "e")
            
            # Different styles for user vs assistant
            if message["sender"] == "user":
                message_frame.configure(fg_color="#00D4A0")  # Turquoise
                text_color = "black"
            else:
                message_frame.configure(fg_color="#2D2D2D" if ctk.get_appearance_mode() == "Dark" else "#EAEAEA")
                text_color = "white" if ctk.get_appearance_mode() == "Dark" else "black"
            
            # Message content
            message_text = ctk.CTkLabel(
                message_frame,
                text=message["text"],
                font=ctk.CTkFont(family="IBM Plex Mono", size=12),
                wraplength=500,
                justify="left",
                text_color=text_color
            )
            message_text.pack(padx=10, pady=10)
            
            # Timestamp
            time_label = ctk.CTkLabel(
                message_frame,
                text=message["time"],
                font=ctk.CTkFont(family="IBM Plex Mono", size=10),
                text_color=text_color
            )
            time_label.pack(padx=10, pady=(0, 5), anchor="e")
    
    def _add_user_message(self, text):
        """Add a user message to the chat"""
        timestamp = datetime.now().strftime("%I:%M %p")
        self.chat_messages.append({
            "sender": "user",
            "text": text,
            "time": timestamp
        })
        self._display_chat_messages()
    
    def _add_assistant_message(self, text):
        """Add an assistant message to the chat"""
        timestamp = datetime.now().strftime("%I:%M %p")
        self.chat_messages.append({
            "sender": "assistant",
            "text": text,
            "time": timestamp
        })
        self._display_chat_messages()
    
    def _on_message_enter(self, event):
        """Handle Enter key in message input"""
        # Check if shift is held down (for newline)
        if event.state & 0x1:  # Shift key
            return
        
        # Prevent the default newline
        event.widget.delete("insert")
        
        # Send the message
        self._send_message()
        
        # Prevent the event from propagating
        return "break"
    
    def _send_message(self):
        """Send a message from the user input"""
        message = self.message_input.get("1.0", "end-1c").strip()
        
        if not message:
            return
        
        # Clear input
        self.message_input.delete("1.0", "end")
        
        # Add user message to chat
        self._add_user_message(message)
        
        # Generate fake response - in a real app, this would call the server
        self._process_user_message(message)
    
    def _process_user_message(self, message):
        """Process a user message and generate a response"""
        # In a real implementation, this would send the query to the server
        # and get a proper response based on the user's data
        
        # For demo purposes, just simulate a response
        self.server_comms.query_activity(
            message,
            callback=self._handle_server_response
        )
    
    def _handle_server_response(self, response):
        """Handle the response from the server"""
        if response and response.get("status") == "success":
            self._add_assistant_message(response.get("response", "I couldn't find any information related to your question."))
        else:
            self._add_assistant_message(
                "I'm sorry, I couldn't process your request at this time. Please check your "
                "internet connection and try again."
            )
    
    def _update_status_loop(self):
        """Update the connection status indicator periodically"""
        while True:
            try:
                # Skip if privacy mode is on
                if self.privacy_mode:
                    time.sleep(5)
                    continue
                
                # Check server connectivity
                is_connected = self.server_comms.check_connectivity()
                
                if is_connected:
                    self.status_indicator.configure(text_color="#00D4A0")  # Turquoise
                    self.status_label.configure(text="Online")
                else:
                    self.status_indicator.configure(text_color="#E74C3C")  # Red
                    self.status_label.configure(text="Offline")
            except Exception as e:
                self.logger.error(f"Error in status update: {str(e)}")
            
            # Check every 5 seconds
            time.sleep(5)

#########################################
# MAIN APPLICATION
#########################################

def signal_handler(sig, frame):
    """Handle exit signals gracefully"""
    global running
    logger = logging.getLogger("integrity")
    logger.info("Shutdown signal received, cleaning up...")
    running = False
    
    # Let threads complete their work
    time.sleep(1)
    
    logger.info("Integrity Assistant shutdown complete")
    sys.exit(0)

def main():
    """Main application entry point"""
    global running
    
    # Set up machine ID
    os.environ['INTEGRITY_MACHINE_ID'] = generate_machine_id()
    
    # Set up logging
    log_level = logging.INFO
    logger = setup_logging(log_level)
    logger.info("Starting Integrity Assistant...")
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Load configuration
        config = Config()
        
        # Set up log file if configured
        if config.get("logs_dir"):
            log_file = os.path.join(config.get("logs_dir"), "integrity.log")
            logger = setup_logging(
                getattr(logging, config.get("log_level", "INFO")), 
                log_file
            )
        
        # Initialize components
        logger.info("Initializing components...")
        
        # Create data queue
        data_queue = queue.Queue()
        
        # Initialize authentication
        auth = SupabaseAuth(
            config.get("supabase_url"),
            config.get("supabase_key")
        )
        
        # Initialize data manager
        data_manager = DataManager(
            config.get("data_dir"),
            config.get("screenshots_dir"),
            config.get("retention_days", 7)
        )
        
        # Initialize server communication
        server_comms = ServerCommunication(
            config.get("server_url"),
            auth
        )
        
        # Initialize screenshot manager
        screenshot_manager = ScreenshotManager(
            data_queue,
            config.get("screenshots_dir"),
            capture_interval=config.get("screenshot_interval", 0.5)
        )
        
        # Initialize keylogger
        keylogger = KeyLogger(
            data_queue
        )
        
        # Start data processor thread
        running = True
        
        def data_processor_thread():
            """Process data from the queue and send to server"""
            logger.info("Starting data processor thread")
            
            while running:
                try:
                    # Process up to 10 items in one batch or wait for 5 seconds
                    batch = []
                    batch_size = 0
                    max_batch_size = 500 * 1024  # 500KB max batch size
                    
                    try:
                        # Block for up to 5 seconds waiting for first item
                        item = data_queue.get(timeout=5)
                        batch.append(item)
                        batch_size += len(json.dumps(item).encode('utf-8'))
                        data_queue.task_done()
                    except queue.Empty:
                        # No data available, skip this cycle
                        continue
                        
                    # Try to get more items without blocking
                    for _ in range(9):  # Up to 9 more items (10 total)
                        try:
                            item = data_queue.get_nowait()
                            item_size = len(json.dumps(item).encode('utf-8'))
                            
                            # Only add if it doesn't exceed max batch size
                            if batch_size + item_size <= max_batch_size:
                                batch.append(item)
                                batch_size += item_size
                            else:
                                # Put it back and process in next batch
                                data_queue.put(item)
                                break
                                
                            data_queue.task_done()
                        except queue.Empty:
                            break
                    
                    if batch:
                        # Encrypt and send data
                        encrypted_data = encrypt_data(json.dumps(batch), config.get("encryption_key"))
                        success = server_comms.send_data(encrypted_data)
                        
                        if not success:
                            logger.warning("Failed to send data to server, queueing for retry")
                            # Store locally for retry
                            data_manager.store_pending_data(batch)
                            
                except Exception as e:
                    logger.error(f"Error in data processor: {str(e)}")
                    logger.error(traceback.format_exc())
                    
                # Sleep a little to prevent CPU overuse
                time.sleep(0.1)
            
            logger.info("Data processor thread stopped")
        
        # Start retry thread
        def retry_pending_data_thread():
            """Retry sending pending data periodically"""
            logger.info("Starting retry thread")
            
            while running:
                try:
                    # Check for connectivity first
                    if server_comms.check_connectivity():
                        # Get pending data batches
                        pending_batches = data_manager.get_pending_data(limit=5)
                        
                        for batch in pending_batches:
                            # Encrypt and send data
                            encrypted_data = encrypt_data(json.dumps(batch), config.get("encryption_key"))
                            success = server_comms.send_data(encrypted_data)
                            
                            if success:
                                # Remove from pending data
                                data_manager.remove_pending_data(batch)
                            else:
                                # Stop trying for now, will retry next cycle
                                break
                except Exception as e:
                    logger.error(f"Error in retry thread: {str(e)}")
                    
                # Check every 5 minutes
                time.sleep(300)
            
            logger.info("Retry thread stopped")
        
        # Start cleanup thread
        def cleanup_thread():
            """Periodic cleanup of old screenshots and data"""
            logger.info("Starting cleanup thread")
            
            while running:
                try:
                    # Perform cleanup based on retention settings
                    data_manager.cleanup_old_data()
                    
                    # Log statistics
                    stats = data_manager.get_statistics()
                    logger.info(f"Storage stats: {stats}")
                    
                except Exception as e:
                    logger.error(f"Error in cleanup thread: {str(e)}")
                    
                # Run once per hour
                time.sleep(3600)
            
            logger.info("Cleanup thread stopped")
        
        # Start threads
        processor_thread = threading.Thread(target=data_processor_thread, daemon=True)
        processor_thread.start()
        
        retry_thread = threading.Thread(target=retry_pending_data_thread, daemon=True)
        retry_thread.start()
        
        cleanup_thread_instance = threading.Thread(target=cleanup_thread, daemon=True)
        cleanup_thread_instance.start()
        
        # Start services
        screenshot_manager.start()
        keylogger.start()
        
        # Initialize GUI (must be last since it starts the main loop)
        logger.info("Initializing GUI...")
        gui = IntegrityGUI(
            config,
            auth,
            server_comms,
            screenshot_manager,
            keylogger,
            data_manager
        )
        
        # Start the GUI (this blocks until GUI is closed)
        gui.start()
        
    except Exception as e:
        logger.error(f"Initialization error: {str(e)}")
        logger.error(traceback.format_exc())
        messagebox.showerror(
            "Initialization Error",
            f"Failed to initialize Integrity Assistant: {str(e)}\n\nPlease check the logs for details."
        )
        sys.exit(1)
    finally:
        # Ensure everything is stopped
        running = False
        
        # Stop components
        if 'keylogger' in locals():
            keylogger.stop()
        if 'screenshot_manager' in locals():
            screenshot_manager.stop()
        if 'server_comms' in locals():
            server_comms.stop()
        
        logger.info("Integrity Assistant shutdown complete")

if __name__ == "__main__":
    main()