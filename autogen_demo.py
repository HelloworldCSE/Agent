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
        "temperature": 0.4,
        "max_tokens": 1500
    }
    response = requests.post(API_URL, headers=HEADERS, json=payload)
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]

def hash_code(code: str) -> str:
    return hashlib.sha256(code.strip().encode()).hexdigest()


# ======================== INPUT CODE =========================

code_to_analyze = """
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # ❌ Vulnerability: SQL Injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()

    # ❌ Vulnerability: No password hashing
    if user:
        return "Login successful"
    else:
        return "Invalid credentials"

@app.route('/admin/delete', methods=['GET'])
def delete_all_users():
    # ❌ Vulnerability: No authentication or authorization
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users")
    conn.commit()
    return "All users deleted"
"""


# ===================== SCANNER AGENT PROMPT =====================

scanner_prompt = [
    {
        "role": "system",
        "content":
            "You are ScannerAgent, a security auditor for Python applications. Analyze only for actual, exploitable vulnerabilities such as injection, broken authentication, insecure cryptography, or poor session handling.\n\n"
            "Only reply with one of the following:\n"
            "- 'No vulnerabilities found.' (exact string)\n"
            "- The code with exact vulnerable lines copied and a short vulnerability reason above each one (in plain English, no comments or markdown).\n\n"
            "Do not suggest improvements, formatting changes, performance tips, or modify any code.\n"
            "Do not rename, remove, or restructure any part of the code.\n"
            "Do not add comments or wrap responses in markdown.\n\n"
            "Presume the code may be integrated across a large codebase. Only real threats should be flagged."
    },
    {"role": "user", "content": f"Scan this code:\n```python\n{code_to_analyze}\n```"}
]
print("Starting security scan...")
scanner_output = ask_mistral(scanner_prompt)

if "no vulnerabilities found" in scanner_output.strip().lower():
    print("No vulnerabilities found.")
    exit()


# ===================== FIXER AGENT PROMPT ======================

def fix_code(code):
    fixer_prompt = [
        {
            "role": "system",
            "content":
                "You are FixerAgent. Resolve only confirmed security vulnerabilities present in the input code.\n\n"
                "  You MUST:\n"
                "- Preserve all function names, variable names, logic, and structure.\n"
                "- Add in-line comments **only where you fix** a security issue, using this format:\n"
                "  # [FixerAgent]: explain the applied fix\n"
                "- Use minimal and targeted changes that do not affect application behavior.\n\n"
                "- Do NOT Refactor the code.\n"
                "- Do NOT Rename functions or variables.\n"
                "- Do NOT Remove existing logic or restructure control flow.\n"
                "- Do NOT Add explanations outside the code.\n\n"
                "Assume that this file is used by other files and changes must not break compatibility."
        },
        {"role": "user", "content": f"Fix this code:\n```python\n{code}\n```"}
    ]
    print("Starting code fixing...")
    return ask_mistral(fixer_prompt)


# ==================== TESTER AGENT PROMPT ======================

def test_code(code):
    tester_prompt = [
        {
            "role": "system",
            "content":
                "You are TesterAgent. Evaluate the fixed code and identify areas that require testing related only to the security vulnerabilities that were fixed.\n\n"
                "If no testing is required, respond exactly with:\n"
                "No additional test suggestions.\n\n"
                "Do not modify or comment the code. Do not generate any code or explanations."
        },
        {"role": "user", "content": f"Here's the code:\n```python\n{code}\n```"}
    ]
    print("Starting code testing...")
    return ask_mistral(tester_prompt)


# ================= FIXER–TESTER LOOP ==========================

current_code = fix_code(scanner_output)
prev_hash = ""
max_iterations = 3

for _ in range(max_iterations):
    test_output = test_code(current_code)
    current_hash = hash_code(test_output)

    if "no additional test suggestions" in test_output.strip().lower() or current_hash == prev_hash:
        break
    print("Applying fixes based on test feedback...")
    current_code = fix_code(current_code)
    prev_hash = current_hash


# ==================== VALIDATOR AGENT PROMPT ===================

validator_prompt = [
    {
        "role": "system",
        "content":
            "You are ValidatorAgent. Finalize and return the secure version of the Python code.\n\n"
            "Preserve all FixerAgent in-line comments.\n"
            "Do not alter logic, structure, or identifiers.\n"
            "Do not re-comment, explain, or format.\n"
            "Return the code only, exactly as it should appear in production."
    },
    {"role": "user", "content": f"Please review this final version:\n```python\n{current_code}\n```"}
]
print("Validate secure code...")
final_code = ask_mistral(validator_prompt)

# ========================= OUTPUT ============================

print("\nCorrected Secure Code:\n")
print(final_code.strip())
