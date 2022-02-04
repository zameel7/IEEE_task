from datetime import date
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from threading import Thread

from helpers import apology, login_required

# Configure application
app = Flask(__name__, template_folder='templates', static_folder='static')

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///dbase.db")


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        events = db.execute("SELECT * FROM events")
        l = len(events)
        return render_template("index.html", events=events, l=l)
    else:
        ft = request.form.get("filter")
        if not ft:
            flash("Select a category to filter")
            return redirect("/")
        else:
            events = db.execute("SELECT * FROM events WHERE categ=?", ft.upper())
            l = len(events)
            return render_template("index.html", events=events, l=l)

@app.route("/addevent", methods=["GET", "POST"])
@login_required
def addevent():
    if request.method == "GET":
        return render_template("addevent.html")
    else:
        dt = date.today()
        ename = request.form.get("event")
        categ = request.form.get("categ")
        edate = request.form.get("dt")
        edesc = request.form.get("edesc")
        if not ename or not edate or not edesc or not categ:
            flash("Enter all details")
        else:
            db.execute("INSERT INTO events (user, ename, edate, edesc, dt, categ) VALUES (?, ?, ?, ?, ?, ?)", session["user_id"], ename, edate, edesc, dt, categ)
            flash("Successfully added!")
        return redirect("/addevent")

@app.route("/delevent", methods=["GET", "POST"])
@login_required
def delevent():
    if request.method == "GET":
        return render_template("delevent.html", events=db.execute("SELECT * FROM events WHERE user=?", session["user_id"]))
    else:
        event = request.form.get("event")
        db.execute("DELETE FROM events WHERE ename=?", event)
        flash("Event deleted successfully!")
        return redirect("/delevent")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
                rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["username"] = (db.execute("SELECT username FROM users WHERE id=?", session["user_id"]))[0]["username"]
        print(session["username"])

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        # Store name in name and password in db and check if previously exist
        name = request.form.get("username")
        prev = db.execute(
            "SELECT EXISTS(SELECT * FROM users WHERE username = ?) ", name)
        prev = [i for i in prev[0].items()]
        if prev[0][1] or not name:
            return apology("Username invalid or not available")

        # Check if passwords match
        password = request.form.get("password")
        confirm = request.form.get("confirmation")
        if not password or password != confirm:
            return apology("Password invalid")

        # Store the details in the database
        else:
            hash = generate_password_hash(password,
                                          method='pbkdf2:sha256',
                                          salt_length=8)
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", name,
                       hash)
            flash("User had been registered successfully!")
            return redirect("/")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    flash("Logged out")
    return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

if __name__ == '__main__':
    # Run the Flask app
    t = Thread(target=app.run(host='0.0.0.0', port=8080, debug=True))
    t.start()
