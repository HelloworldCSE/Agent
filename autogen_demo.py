import os
import requests
import hashlib
from typing import List, Dict
from config import MISTRAL_API_KEY, MISTRAL_API_URL

class MistralAPI:
    def __init__(self, api_key: str, api_url: str):
        self.api_key = api_key
        self.api_url = api_url
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

    def ask(self, messages: List[Dict]) -> str:
        payload = {
            "model": "mistral-medium",
            "messages": messages,
            "temperature": 0.4,
            "max_tokens": 1500
        }
        response = requests.post(self.api_url, headers=self.headers, json=payload)
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]


def hash_code(code: str) -> str:
    return hashlib.sha256(code.strip().encode()).hexdigest()


def scan_code(api: MistralAPI, code: str) -> str:
    scanner_prompt = [
        {
            "role": "system",
            "content": (
                "You are ScannerAgent, a security auditor. Your role is to analyze the provided code (in any language) for actual, exploitable vulnerabilities such as injection, broken authentication, insecure cryptography, or poor session handling.\n\n"
                "Only reply with one of the following:\n"
                "- 'No vulnerabilities found.' (exact string)\n"
                "- The code with exact vulnerable lines copied and a short vulnerability reason above each one (in plain English, no comments or markdown).\n\n"
                "You MUST NOT add, modify, or remove any code, comments, or structure.\n"
                "You MUST NOT add any comments or explanations in the code.\n"
                "You MUST NOT suggest improvements, formatting changes, or performance tips.\n"
                "You MUST NOT rename, remove, or restructure any part of the code.\n\n"
                "Presume the code may be integrated across a large codebase in any language. Only real threats should be flagged."
            )
        },
        {"role": "user", "content": f"Scan this code:\n```\n{code}\n```"}
    ]
    print("Starting security scan...")
    return api.ask(scanner_prompt)


def fix_code(api: MistralAPI, code: str) -> str:
    fixer_prompt = [
        {
            "role": "system",
            "content": (
                "You are FixerAgent. Your role is to resolve only confirmed security vulnerabilities present in the input code (in any language).\n\n"
                "  You MUST:\n"
                "- Preserve all function names, variable names, logic, and structure.\n"
                "- Add in-line comments **only where you fix** a security issue, using this format:\n"
                "  # [FixerAgent]: explain the applied fix\n"
                "- Use minimal and targeted changes that do not affect application behavior.\n\n"
                "- Do NOT refactor the code.\n"
                "- Do NOT rename functions or variables.\n"
                "- Do NOT remove existing logic or restructure control flow.\n"
                "- Do NOT add explanations outside the code.\n"
                "- Do NOT add comments except for the fixes you apply.\n\n"
                "Assume that this file is used by other files and changes must not break compatibility."
            )
        },
        {"role": "user", "content": f"Fix this code:\n```\n{code}\n```"}
    ]
    print("Starting code fixing...")
    return api.ask(fixer_prompt)


def test_code(api: MistralAPI, code: str) -> str:
    tester_prompt = [
        {
            "role": "system",
            "content": (
                "You are TesterAgent. Your role is to evaluate the fixed code and identify areas that require testing related only to the security vulnerabilities that were fixed.\n\n"
                "If no testing is required, respond exactly with:\n"
                "No additional test suggestions.\n\n"
                "You MUST NOT modify, comment, or generate any code.\n"
                "You MUST NOT add any comments or explanations in the code.\n"
                "You MUST NOT add explanations outside the code."
            )
        },
        {"role": "user", "content": f"Here's the code:\n```\n{code}\n```"}
    ]
    print("Starting code testing...")
    return api.ask(tester_prompt)


def validate_code(api: MistralAPI, code: str) -> str:
    validator_prompt = [
        {
            "role": "system",
            "content": (
                "You are ValidatorAgent. Your role is to finalize and return the complete, secure version of the code (in any language).\n\n"
                "You MUST:\n"
                "- Output the entire, corrected code file, not just the changes or a diff.\n"
                "- Preserve all FixerAgent in-line comments.\n"
                "- Make no functional changes except for confirmed security fixes.\n"
                "- Do NOT alter logic, structure, or identifiers except as required for the security fix.\n"
                "- Do NOT add, modify, or remove any comments except those added by FixerAgent.\n"
                "- Do NOT re-comment, explain, or format.\n"
                "Return the full code only, exactly as it should appear in production."
            )
        },
        {"role": "user", "content": f"Please review this final version and return the complete, corrected code file:\n```\n{code}\n```"}
    ]
    print("Validate secure code...")
    return api.ask(validator_prompt)


def main():
    api = MistralAPI(MISTRAL_API_KEY, MISTRAL_API_URL)
    code_to_analyze = """
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Vulnerable to SQL Injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()

    if user:
        return "Login successful"
    else:
        return "Invalid credentials"

@app.route('/admin/delete', methods=['GET'])
def delete_all_users():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users")
    conn.commit()
    return "All users deleted"
"""

    scanner_output = scan_code(api, code_to_analyze)
    if "no vulnerabilities found" in scanner_output.strip().lower():
        print("No vulnerabilities found.")
        return

    current_code = fix_code(api, scanner_output)
    prev_hash = ""
    max_iterations = 3

    for _ in range(max_iterations):
        test_output = test_code(api, current_code)
        current_hash = hash_code(test_output)
        if "no additional test suggestions" in test_output.strip().lower() or current_hash == prev_hash:
            break
        print("Applying fixes based on test feedback...")
        current_code = fix_code(api, current_code)
        prev_hash = current_hash

    final_code = validate_code(api, current_code)
    print("\nCorrected Secure Code:\n")
    print(final_code.strip())


if __name__ == "__main__":
    main() 
