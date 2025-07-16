from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/")
def home():
    return "CTEM vulnerable app running."

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    #Intentional SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}';"
    con = sqlite3.connect('users.db')
    cur = con.cursor()
    cur.execute(query)
    user = cur.fetchone()
    con.close()
    if user:
        return "Login successful"
    else:
        return "Invalid credentials", 401
