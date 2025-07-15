import requests
import hashlib

# ========================== CONFIG ==========================
API_KEY = "KCejQ3UJ3AyYTqs4EDuIsXPQbNHYlByO"
API_URL = "https://api.mistral.ai/v1/chat/completions"

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

def ask_mistral(messages):
    payload = {
        "model": "mistral-medium",
        "messages": messages,
        "temperature": 0.7,
        "max_tokens": 1000
    }
    response = requests.post(API_URL, headers=HEADERS, json=payload)
    response.raise_for_status()
    try:
        return response.json()["choices"][0]["message"]["content"]
    except (KeyError, IndexError):
        return "[ERROR] Invalid response from Mistral."

def hash_code(code: str) -> str:
    return hashlib.sha256(code.strip().encode()).hexdigest()

# ======================== INPUT CODE =========================
code_to_analyze = """from flask import Flask, request
import sqlite3
import hashlib
import os
import secrets
from flask.templating import render_template_string

app = Flask(__name__)

app.secret_key = os.urandom(24) # [FixerAgent]: Changed from fixed value to random generation
app.config['SESSION_COOKIE_SECURE'] = True # [FixerAgent]: Ensure session cookies are secure
app.config['SESSION_COOKIE_HTTPONLY'] = True # [FixerAgent]: Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # [FixerAgent]: Add SameSite protection

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()

    if not username or not password:
        return render_template_string("Username and password are required"), 400 # [FixerAgent]: Use template rendering instead of direct string

    query = "SELECT password FROM users WHERE username = ?"

    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()

    cursor.execute("SELECT password, salt FROM users WHERE username = ?", (username,))
    user_data = cursor.fetchone()
    conn.close()

    if user_data:
        stored_password_hash, salt = user_data
        input_password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()
        if secrets.compare_digest(input_password_hash, stored_password_hash):
            response = render_template_string("Login successful") # [FixerAgent]: Use template rendering instead of direct string
            return response
        else:
            return render_template_string("Invalid credentials"), 401 # [FixerAgent]: Use template rendering and proper status code
    else:
        return render_template_string("Invalid credentials"), 401 # [FixerAgent]: Use template rendering and proper status code

@app.route('/admin/delete', methods=['GET'])
def delete_all_users():
    if not secrets.compare_digest(request.headers.get('X-Admin-Key', ''), os.getenv('ADMIN_KEY', secrets.token_hex(32))): # [FixerAgent]: Use random default admin key
        return render_template_string("Unauthorized"), 401 # [FixerAgent]: Use template rendering instead of direct string

    if not request.is_secure:
        return render_template_string("This operation requires HTTPS"), 403 # [FixerAgent]: Use template rendering instead of direct string

    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users")
    conn.commit()
    conn.close()
    return render_template_string("All users deleted") # [FixerAgent]: Use template rendering instead of direct string
"""

# ======================= SCANNER AGENT =======================
scanner_prompt = [
    {
        "role": "system",
        "content": (
            "You are ScannerAgent. Objectively analyze the given Python code for real security vulnerabilities "
            "such as SQL injection, XSS, broken authentication, insecure input handling, or poor error handling.\n\n"
            "✅ If no real security vulnerabilities are found, reply exactly:\n"
            "✅ No vulnerabilities found.\n\n"
            "📌 If vulnerabilities exist, add only **in-line comments** like:\n"
            "# [ScannerAgent]: Describe the exact vulnerability above the affected line\n\n"
            "❌ Do NOT suggest performance, readability, or stylistic changes\n"
            "❌ Do NOT rename functions, variables, or change logic"
        )
    },
    {"role": "user", "content": f"Scan this code:\n```python\n{code_to_analyze}\n```"}
]
print("scan")
scanner_output = ask_mistral(scanner_prompt)

if "no vulnerabilities found" in scanner_output.strip().lower():
    print("✅ No vulnerabilities found.")
    exit()

# ======================= FIXER AGENT =========================
def fix_code(code):
    fixer_prompt = [
        {
            "role": "system",
            "content": (
                "You are FixerAgent. Fix ONLY the **security vulnerabilities** in the code while preserving all function names, logic, and external interface contracts.\n\n"
                "✅ You MUST:\n"
                "- Add only in-line fix comments like `# [FixerAgent]: your fix`\n"
                "- Leave all business logic, function names, and parameters unchanged\n"
                "- Focus on minimal secure code patches\n\n"
                "❌ Do NOT rename functions, variables, or classes\n"
                "❌ Do NOT refactor, reorder logic, or add docstrings\n"
                "❌ Do NOT explain anything outside the code"
            )
        },
        {"role": "user", "content": f"Fix this code:\n```python\n{code}\n```"}
    ]
    print("fix")
    return ask_mistral(fixer_prompt)

# ======================= TESTER AGENT ========================
def test_code(code):
    tester_prompt = [
        {
            "role": "system",
            "content": (
                "You are TesterAgent. Suggest test cases for the fixed code, but only via **in-line test suggestions** "
                "as comments like `# [TesterAgent]: test suggestion here`.\n\n"
                "✅ Only suggest tests relevant to fixed security issues\n"
                "❌ Do NOT write actual test code\n"
                "❌ Do NOT suggest renaming, modifying, or refactoring\n"
                "❌ If no tests are needed, reply exactly: No additional test suggestions."
            )
        },
        {"role": "user", "content": f"Here's the code:\n```python\n{code}\n```"}
    ]
    print("test")
    return ask_mistral(tester_prompt)

# ========== LOOP FIXER <--> TESTER UNTIL NO MORE TEST INPUT ==========
current_code = fix_code(scanner_output)
prev_hash = ""
max_iterations = 3

for _ in range(max_iterations):
    tested_code = test_code(current_code)
    current_hash = hash_code(tested_code)

    if "no additional test suggestions" in tested_code.strip().lower() or current_hash == prev_hash:
        break
    print("🔄 Iteration: Fixing code based on test suggestions...")
    current_code = fix_code(tested_code)
    prev_hash = current_hash

# ====================== VALIDATOR AGENT ======================
validator_prompt = [
    {
        "role": "system",
        "content": (
            "You are ValidatorAgent. Perform a final review and return the secure, validated code.\n\n"
            "✅ Keep all previous in-line agent comments\n"
            "✅ Return the code only (no docstrings, explanations, or markdown formatting)\n"
            "❌ Do NOT modify the code or comment outside what’s already been done"
        )
    },
    {"role": "user", "content": f"Please review this final version:\n```python\n{current_code}\n```"}
]
print("validate")
final_code = ask_mistral(validator_prompt)

# ========================= OUTPUT ============================
print("\n🔐 Final Reviewed Code:\n")
print(final_code.strip())
