import os
import subprocess
import pickle
import requests

# ===== Vulnerable global data =====
user_passwords = {
    "admin": "supersecret",
    "guest": "guestpass"
}

# Vulnerability 1: Unsafe eval
def run_user_input():
    user_code = input("Enter some Python code: ")
    eval(user_code)  # Dangerous: arbitrary code execution

# Vulnerability 2: Unsafe exec
def run_commands():
    command = input("Enter a command to run: ")
    exec(command)  # Dangerous: arbitrary code execution

# Vulnerability 3: Hardcoded passwords
def check_password(user):
    pwd = user_passwords.get(user)
    if pwd:
        print(f"Password for {user} is {pwd}")
    else:
        print("User not found")

# Vulnerability 4: Pickle deserialization
def load_pickle_file(filename):
    with open(filename, "rb") as f:
        data = pickle.load(f)  # Unsafe if file is untrusted
    print("Loaded data:", data)

# Vulnerability 5: Subprocess shell injection
def dangerous_subprocess():
    cmd = input("Enter system command: ")
    subprocess.run(cmd, shell=True)  # shell=True is unsafe

# Vulnerability 6: Insecure HTTP request
def insecure_request():
    r = requests.get("https://example.com", verify=False)  # TLS verification disabled
    print(r.text[:100])

# ===== Safe code for contrast =====
def safe_function():
    print("This is safe code.")
    numbers = [1, 2, 3, 4]
    squared = [x**2 for x in numbers]
    print("Squares:", squared)

def safe_file_read(filename):
    # Only allow reading files from 'data' folder
    base_path = os.path.abspath("data")
    file_path = os.path.abspath(filename)
    if not file_path.startswith(base_path):
        print("Unauthorized file access attempt")
        return
    with open(file_path, "r") as f:
        for line in f:
            print(line.strip())

if __name__ == "__main__":
    # Run a mix of vulnerable and safe functions
    try:
        safe_function()
        # Commented out user input functions for automated testing
        # run_user_input()
        # run_commands()
        check_password("admin")
        # load_pickle_file("data/sample.pkl")
        # dangerous_subprocess()
        # insecure_request()
        safe_file_read("data/sample.txt")
    except Exception as e:
        print("Error:", e)
