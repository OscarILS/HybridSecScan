"""
Aplicación vulnerable intencional para pruebas SAST
Contiene vulnerabilidades comunes encontradas por Bandit
"""

import os
import pickle
import subprocess
import tempfile
from flask import Flask, request, render_template_string

app = Flask(__name__)

# VULNERABILIDAD 1: Hardcoded password/secret
SECRET_KEY = "admin123password"
DATABASE_PASSWORD = "root_password_123"

# VULNERABILIDAD 2: SQL Injection
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    # db.execute(query)
    return f"Query: {query}"

# VULNERABILIDAD 3: Command Injection
@app.route('/execute', methods=['POST'])
def execute_command():
    cmd = request.form.get('command')
    # Command Injection vulnerability
    result = os.system(cmd)
    return f"Command executed: {result}"

# VULNERABILIDAD 4: Insecure deserialization
@app.route('/deserialize', methods=['POST'])
def deserialize():
    data = request.files['data']
    # Pickle deserialization vulnerability
    obj = pickle.load(data)
    return f"Deserialized: {obj}"

# VULNERABILIDAD 5: Path traversal
@app.route('/read_file', methods=['GET'])
def read_file():
    filename = request.args.get('file')
    # Path traversal vulnerability
    with open(filename, 'r') as f:
        return f.read()

# VULNERABILIDAD 6: Temporary file
@app.route('/process', methods=['POST'])
def process_file():
    # Insecure temporary file
    temp_file = tempfile.mktemp()
    with open(temp_file, 'w') as f:
        f.write(request.form.get('data'))
    return f"Processed: {temp_file}"

# VULNERABILIDAD 7: Use of assert for validation
@app.route('/validate', methods=['POST'])
def validate_input():
    user_input = request.form.get('input')
    # Using assert for validation (will be optimized away)
    assert len(user_input) > 0, "Input cannot be empty"
    return "Validated"

# VULNERABILIDAD 8: Insecure random
@app.route('/token', methods=['GET'])
def generate_token():
    import random
    import string
    # Insecure random for security token
    token = ''.join(random.choice(string.ascii_letters) for _ in range(32))
    return f"Token: {token}"

# VULNERABILIDAD 9: Flask run with debug=True in production
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
