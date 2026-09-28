from flask import (
    Flask, render_template, request,
    redirect, url_for, session
)

import sqlite3
from pathlib import Path
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# ==========================================
# FLASK APPLICATION
# ==========================================

app = Flask(__name__)

app.secret_key = "personal_expenses_tracker_secret_key"


# ==========================================
# DATABASE CONNECTION
# ==========================================

# Always use database.db from the same folder as app.py
BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "database.db"


def get_db_connection():
    conn = sqlite3.connect(str(DATABASE_PATH))
    return conn


# ==========================================
# CREATE DATABASE TABLES
# ==========================================

def init_db():

    conn = get_db_connection()
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # Expenses table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            category TEXT NOT NULL,
            date TEXT NOT NULL,
            description TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Income table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS income (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            source TEXT NOT NULL,
            date TEXT NOT NULL,
            description TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()


# ==========================================
# LOGIN
# ==========================================

@app.route("/", methods=["GET", "POST"])
def home():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            return "Please enter your email and password."

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, name, email, password
            FROM users
            WHERE LOWER(TRIM(email)) = ?
        """, (email,))

        user = cursor.fetchone()

        if user is None:
            conn.close()
            return "Invalid email or password."

        stored_password = user[3]

        password_is_valid = False

        # Check hashed passwords
        try:
            password_is_valid = check_password_hash(
                stored_password, password
            )
        except (ValueError, TypeError):
            password_is_valid = False

        # Support older accounts saved with plain-text passwords
        if not password_is_valid:
            if not stored_password.startswith(
                ("scrypt:", "pbkdf2:")
            ):
                password_is_valid = (
                    stored_password == password
                )

                # Convert an old plain-text password to a hash
                if password_is_valid:

                    new_hash = generate_password_hash(password)

                    cursor.execute("""
                        UPDATE users
                        SET password = ?
                        WHERE id = ?
                    """, (new_hash, user[0]))

                    conn.commit()

        conn.close()

        if password_is_valid:

            session.clear()
            session["user_id"] = user[0]
            session["user_name"] = user[1]

            return redirect(url_for("dashboard"))

        return "Invalid email or password."

    return render_template("index.html")


# ==========================================
# SIGNUP
# ==========================================

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            return "Please fill in all the required fields."

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        try:

            cursor.execute("""
                INSERT INTO users (name, email, password)
                VALUES (?, ?, ?)
            """, (name, email, hashed_password))

            conn.commit()

        except sqlite3.IntegrityError:

            conn.close()
            return "This email is already registered."

        finally:
            # The connection is closed below after a successful insert.
            pass

        conn.close()

        return redirect(url_for("home"))

    return render_template("signup.html")


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("home"))

    user_id = session["user_id"]

    conn = get_db_connection()
    cursor = conn.cursor()

    # Total expenses
    cursor.execute("""
        SELECT COALESCE(SUM(amount), 0)
        FROM expenses
        WHERE user_id = ?
    """, (user_id,))

    total_expenses = cursor.fetchone()[0]

    # Total income
    cursor.execute("""
        SELECT COALESCE(SUM(amount), 0)
        FROM income
        WHERE user_id = ?
    """, (user_id,))

    total_income = cursor.fetchone()[0]

    # Total balance
    total_balance = total_income - total_expenses

    # Number of expenses
    cursor.execute("""
        SELECT COUNT(*)
        FROM expenses
        WHERE user_id = ?
    """, (user_id,))

    expense_count = cursor.fetchone()[0]

    # Number of income transactions
    cursor.execute("""
        SELECT COUNT(*)
        FROM income
        WHERE user_id = ?
    """, (user_id,))

    income_count = cursor.fetchone()[0]

    # Five most recent expenses
    cursor.execute("""
        SELECT amount, category, date, description
        FROM expenses
        WHERE user_id = ?
        ORDER BY date DESC, id DESC
        LIMIT 5
    """, (user_id,))

    recent_expenses = cursor.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        total_balance=total_balance,
        total_income=total_income,
        total_expenses=total_expenses,
        expense_count=expense_count,
        income_count=income_count,
        recent_expenses=recent_expenses
    )


# ==========================================
# ADD EXPENSE
# ==========================================

@app.route("/add-expense", methods=["GET", "POST"])
def add_expense():

    if "user_id" not in session:
        return redirect(url_for("home"))

    if request.method == "POST":

        amount = request.form.get("amount", "")
        category = request.form.get("category", "").strip()
        date = request.form.get("date", "")
        description = request.form.get(
            "description", ""
        ).strip()

        try:
            amount = float(amount)

            if amount <= 0:
                return "Amount must be greater than zero."

        except (ValueError, TypeError):
            return "Please enter a valid amount."

        if not category or not date:
            return "Please fill in all required fields."

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO expenses
            (user_id, amount, category, date, description)
            VALUES (?, ?, ?, ?, ?)
        """, (
            session["user_id"],
            amount,
            category,
            date,
            description
        ))

        conn.commit()
        conn.close()

        return redirect(url_for("dashboard"))

    return render_template("add_expense.html")


# ==========================================
# ADD INCOME
# ==========================================

@app.route("/add-income", methods=["GET", "POST"])
def add_income():

    if "user_id" not in session:
        return redirect(url_for("home"))

    if request.method == "POST":

        amount = request.form.get("amount", "")
        source = request.form.get("source", "").strip()
        date = request.form.get("date", "")
        description = request.form.get(
            "description", ""
        ).strip()

        try:
            amount = float(amount)

            if amount <= 0:
                return "Amount must be greater than zero."

        except (ValueError, TypeError):
            return "Please enter a valid amount."

        if not source or not date:
            return "Please fill in all required fields."

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO income
            (user_id, amount, source, date, description)
            VALUES (?, ?, ?, ?, ?)
        """, (
            session["user_id"],
            amount,
            source,
            date,
            description
        ))

        conn.commit()
        conn.close()

        return redirect(url_for("dashboard"))

    return render_template("add_income.html")


# ==========================================
# TRANSACTION HISTORY
# ==========================================

@app.route("/transactions")
def transactions():

    if "user_id" not in session:
        return redirect(url_for("home"))

    user_id = session["user_id"]

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch expenses
    cursor.execute("""
        SELECT
            'Expense' AS type,
            category AS title,
            amount,
            date,
            description
        FROM expenses
        WHERE user_id = ?
    """, (user_id,))

    expenses = cursor.fetchall()

    # Fetch income
    cursor.execute("""
        SELECT
            'Income' AS type,
            source AS title,
            amount,
            date,
            description
        FROM income
        WHERE user_id = ?
    """, (user_id,))

    incomes = cursor.fetchall()

    conn.close()

    # Combine income and expenses
    all_transactions = list(expenses) + list(incomes)

    # Sort by date, newest first
    all_transactions.sort(
        key=lambda transaction: transaction[3],
        reverse=True
    )

    return render_template(
        "transactions.html",
        transactions=all_transactions
    )


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("home"))


# ==========================================
# RUN THE APPLICATION
# ==========================================

if __name__ == "__main__":

    init_db()

    print("Database location:", DATABASE_PATH)

    app.run(debug=True)