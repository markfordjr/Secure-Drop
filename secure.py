import sys
import json
import getpass
from pathlib import Path
import bcrypt
from cryptography.fernet import Fernet
import hashlib
import os
import time

# Environmental configuration
KEY_FILE = os.getenv('ENCRYPTION_KEY_PATH', 'encryption.key')
CLIENT_ID = sys.argv[1] if len(sys.argv) > 1 else None

# Functions for file paths
def get_user_file_path(client_id):
    return f"{client_id}_users.json"

def get_contact_file_path(client_id):
    return f"{client_id}_contacts.json"

# Encryption setup
def setup_encryption_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, 'rb') as key_file:
            key = key_file.read()
    return Fernet(key)

cipher_suite = setup_encryption_key()

# JSON file management
def load_json(path):
    try:
        if os.path.exists(path):
            with open(path, 'r') as file:
                return json.load(file)
    except json.JSONDecodeError:
        return {}
    return {}

def save_json(data, path):
    with open(path, 'w') as file:
        json.dump(data, file, indent=4)

# Authentication and Session Management
def create_session(email):
    current_time = time.time()
    random_data = os.urandom(16).hex()
    session_token = hashlib.sha256(f"{email}{current_time}{random_data}".encode()).hexdigest()
    return session_token

def end_session(session_token):
    print(f"Session ended for {session_token}")

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def check_password(hashed_password, password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# User and Contact Management
def register_user(user_file_path):
    print("Register New User:")
    full_name = input("Enter Full Name: ")
    email = input("Enter Email Address: ")
    password = getpass.getpass("Enter Password: ")
    confirm_password = getpass.getpass("Re-enter Password: ")
    
    if password == confirm_password:
        users = load_json(user_file_path)
        if email not in users:
            users[email] = {'full_name': full_name, 'password': hash_password(password)}
            save_json(users, user_file_path)
            print("User Registered.")
        else:
            print("Email already registered.")
    else:
        print("Passwords do not match.")

def login(user_file_path):
    print("Login:")
    email = input("Enter Email Address: ")
    users = load_json(user_file_path)
    
    if email in users:
        for attempt in range(3):
            password = getpass.getpass("Enter Password: ")
            if check_password(users[email]['password'], password):
                print("Welcome to SecureDrop.")
                return email, create_session(email)
            print(f"Incorrect password. {2 - attempt} tries left.")
    print("User not found or incorrect credentials.")
    return None, None

# Command Loop and Main
def command_loop(user_email, session_token, contact_file_path):
    while True:
        command = input("secure_drop> ").strip().lower()
        if command == 'exit':
            end_session(session_token)
            break
        elif command == 'help':
            print('"add" -> Add a new contact\n"list" -> List all contacts\n"exit" -> Exit SecureDrop')
        elif command == 'add':
            add_contact(contact_file_path, user_email)
        elif command == 'list':
            list_contacts(contact_file_path, user_email)

def main():
    if not CLIENT_ID:
        print("Client ID not specified. Usage: python script.py <client_id>")
        return
    
    user_file_path = get_user_file_path(CLIENT_ID)
    contact_file_path = get_contact_file_path(CLIENT_ID)
    
    if input("Do you want to register a new user (y/n)? ").strip().lower() == 'y':
        register_user(user_file_path)
    else:
        user_email, session_token = login(user_file_path)
        if user_email and session_token:
            command_loop(user_email, session_token, contact_file_path)

if __name__ == "__main__":
    main()