import mysql.connector
from flask import request, render_template_string

# Example 1: SQL Injection vulnerability
def get_user(user_id):
    conn = mysql.connector.connect(user='root', password='password123', host='localhost', database='users')
    cursor = conn.cursor()
    # Vulnerable: Direct string concatenation
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()

# Example 2: XSS vulnerability
@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    # Vulnerable: Unescaped user input
    template = '<h1>Hello ' + name + '!</h1>'
    return render_template_string(template)

# Example 3: Exposed secrets
API_KEY = "sk_test_51HbXN9JKlmnOP123456789"
AWS_SECRET = "AKIA1234567890ABCDEF"

# Example 4: Security misconfiguration
DEBUG = True
ALLOW_ALL_ORIGINS = "*"
JWT_SECRET = "my_super_secret_key"
