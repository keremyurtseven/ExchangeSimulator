import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, symbolChecker

# export API_KEY=pk_33f74b1787424a539d1bf4d38d2dc76 --API KEY for iexCloud--

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    
    # Find stocks that the user has owned
    historyStocks = db.execute("SELECT * FROM users_stock WHERE user_id = ?", session["user_id"])
    totalStocks = []
    
    for row in historyStocks:
        rowDict = {}
        symbolDict = lookup(row["symbol"])
        if symbolChecker(row["symbol"], totalStocks) == -1 and row["type"] == "buy":
            rowDict["symbol"] = row["symbol"]
            rowDict["name"] = symbolDict["name"]
            rowDict["price"] = symbolDict["price"]
            rowDict["share"] = row["shares"]
            rowDict["total"] = float("{:.2f}".format(float(row["shares"]) * symbolDict["price"]))
            
            totalStocks.append(rowDict)
            
        elif symbolChecker(row["symbol"], totalStocks) != -1 and row["type"] == "buy":
            rowN = symbolChecker(row["symbol"], totalStocks)
            totalStocks[rowN]["share"] += int(row["shares"])
            totalStocks[rowN]["total"] += float("{:.2f}".format(float(row["shares"]) * symbolDict["price"]))
        
        elif symbolChecker(row["symbol"], totalStocks) != -1 and row["type"] == "sell":
            rowN = symbolChecker(row["symbol"], totalStocks)
            totalStocks[rowN]["share"] += int(row["shares"])
            totalStocks[rowN]["total"] += float("{:.2f}".format(float(row["shares"]) * symbolDict["price"]))
            
            if totalStocks[rowN]["share"] == 0:
                del totalStocks[rowN]
                
    # Find total value of stokcs and cash
    money = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = money[0]["cash"]
    totalCash = cash
    
    for row in totalStocks:
        totalCash += row["total"]
    
    return render_template("index.html", totalCash=totalCash, money=cash, stocks=totalStocks)


@app.route("/1")
@login_required
def index1():
    """Show portfolio of stocks"""
    
    # Find stocks that the user has owned
    historyStocks = db.execute("SELECT * FROM users_stock WHERE user_id = ?", session["user_id"])
    totalStocks = []
    
    for row in historyStocks:
        rowDict = {}
        symbolDict = lookup(row["symbol"])
        if symbolChecker(row["symbol"], totalStocks) == -1 and row["type"] == "buy":
            rowDict["symbol"] = row["symbol"]
            rowDict["name"] = symbolDict["name"]
            rowDict["price"] = symbolDict["price"]
            rowDict["share"] = row["shares"]
            rowDict["total"] = float("{:.2f}".format(float(row["shares"]) * symbolDict["price"]))
            
            totalStocks.append(rowDict)
            
        elif symbolChecker(row["symbol"], totalStocks) != -1 and row["type"] == "buy":
            rowN = symbolChecker(row["symbol"], totalStocks)
            totalStocks[rowN]["share"] += int(row["shares"])
            totalStocks[rowN]["total"] += float("{:.2f}".format(float(row["shares"]) * symbolDict["price"]))
        
        elif symbolChecker(row["symbol"], totalStocks) != -1 and row["type"] == "sell":
            rowN = symbolChecker(row["symbol"], totalStocks)
            totalStocks[rowN]["share"] += int(row["shares"])
            totalStocks[rowN]["total"] += float("{:.2f}".format(float(row["shares"]) * symbolDict["price"]))
            
            if totalStocks[rowN]["share"] == 0:
                del totalStocks[rowN]
                
    # Find total value of stokcs and cash
    money = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = money[0]["cash"]
    totalCash = cash
    
    for row in totalStocks:
        totalCash += row["total"]
    
    return render_template("index.html", check="password", totalCash=totalCash, money=cash, stocks=totalStocks)


@app.route("/2")
@login_required
def index2():
    """Show portfolio of stocks"""
    
    # Find stocks that the user has owned
    historyStocks = db.execute("SELECT * FROM users_stock WHERE user_id = ?", session["user_id"])
    totalStocks = []
    
    for row in historyStocks:
        rowDict = {}
        symbolDict = lookup(row["symbol"])
        if symbolChecker(row["symbol"], totalStocks) == -1 and row["type"] == "buy":
            rowDict["symbol"] = row["symbol"]
            rowDict["name"] = symbolDict["name"]
            rowDict["price"] = symbolDict["price"]
            rowDict["share"] = row["shares"]
            rowDict["total"] = float("{:.2f}".format(float(row["shares"]) * symbolDict["price"]))
            
            totalStocks.append(rowDict)
            
        elif symbolChecker(row["symbol"], totalStocks) != -1 and row["type"] == "buy":
            rowN = symbolChecker(row["symbol"], totalStocks)
            totalStocks[rowN]["share"] += int(row["shares"])
            totalStocks[rowN]["total"] += float("{:.2f}".format(float(row["shares"]) * symbolDict["price"]))
        
        elif symbolChecker(row["symbol"], totalStocks) != -1 and row["type"] == "sell":
            rowN = symbolChecker(row["symbol"], totalStocks)
            totalStocks[rowN]["share"] += int(row["shares"])
            totalStocks[rowN]["total"] += float("{:.2f}".format(float(row["shares"]) * symbolDict["price"]))
            
            if totalStocks[rowN]["share"] == 0:
                del totalStocks[rowN]
                
    # Find total value of stokcs and cash
    money = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = money[0]["cash"]
    totalCash = cash
    
    for row in totalStocks:
        totalCash += row["total"]
    
    return render_template("index.html", check="sell", totalCash=totalCash, money=cash, stocks=totalStocks)


@app.route("/3")
@login_required
def index3():
    """Show portfolio of stocks"""
    
    # Find stocks that the user has owned
    historyStocks = db.execute("SELECT * FROM users_stock WHERE user_id = ?", session["user_id"])
    totalStocks = []
    
    for row in historyStocks:
        rowDict = {}
        symbolDict = lookup(row["symbol"])
        if symbolChecker(row["symbol"], totalStocks) == -1 and row["type"] == "buy":
            rowDict["symbol"] = row["symbol"]
            rowDict["name"] = symbolDict["name"]
            rowDict["price"] = symbolDict["price"]
            rowDict["share"] = row["shares"]
            rowDict["total"] = float("{:.2f}".format(float(row["shares"]) * symbolDict["price"]))
            
            totalStocks.append(rowDict)
            
        elif symbolChecker(row["symbol"], totalStocks) != -1 and row["type"] == "buy":
            rowN = symbolChecker(row["symbol"], totalStocks)
            totalStocks[rowN]["share"] += int(row["shares"])
            totalStocks[rowN]["total"] += float("{:.2f}".format(float(row["shares"]) * symbolDict["price"]))
        
        elif symbolChecker(row["symbol"], totalStocks) != -1 and row["type"] == "sell":
            rowN = symbolChecker(row["symbol"], totalStocks)
            totalStocks[rowN]["share"] += int(row["shares"])
            totalStocks[rowN]["total"] += float("{:.2f}".format(float(row["shares"]) * symbolDict["price"]))
            
            if totalStocks[rowN]["share"] == 0:
                del totalStocks[rowN]
                
    # Find total value of stokcs and cash
    money = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = money[0]["cash"]
    totalCash = cash
    
    for row in totalStocks:
        totalCash += row["total"]
    
    return render_template("index.html", check="buy", totalCash=totalCash, money=cash, stocks=totalStocks)    
    

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        
        # Ensure symbol is sumbitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)
            
        # Ensure share is submitted
        if not request.form.get("shares"):
            return apology("must provide share", 400)
        
        # Take inputs from quote.html
        symbol = request.form.get("symbol")
        
        # Ensure symbol is valid
        if lookup(symbol) == None:
            return apology("invalid symbol", 400)
        
        # Declare share number
        try:
            share = int(request.form.get("shares"))
        except ValueError:
            return apology("shares must be positive integer", 400)
            
        # Ensure share is valid
        if (int(share)*10) % 10 != 0 or int(share) <= 0:
            return apology("shares must be positive integer", 400)
        
        # Based on lookup function determine price of the stock symbol
        symbolDict = lookup(symbol)
        price = symbolDict["price"]
        
        # Find how much money the user has
        user = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        money = user[0]["cash"]
        
        # Ensure the user has enough money
        if money < (float(share)*price):
            return apology("cash is not enough", 400)
            
        user_stock = db.execute("SELECT * FROM users_stock WHERE user_id = ?", session["user_id"])
        
        db.execute("INSERT INTO users_stock (user_id, symbol, shares, price, type) VALUES(?, ?, ?, ?, ?)",
                   session["user_id"], symbol.upper(), int(share), price, "buy")
        
        money -= float(share)*price
        
        db.execute("UPDATE users SET cash = ? WHERE id = ?", money, session["user_id"])
                    
        return redirect("/3")
        
    # User reached route via GET (as by clicking a link or via redirect) 
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    
    # Create a list of dictionaries consisting of the user's processes
    historyStock = db.execute(
        "SELECT symbol, shares, price, date FROM users_stock WHERE user_id = ? ORDER BY date DESC", session["user_id"])
    
    return render_template("history.html", stocks=historyStock)


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """Change information of the user's account"""
    
    # Declare password and username of the user
    user = db.execute("SELECT username, hash FROM users WHERE id = ?", session["user_id"])
    password = user[0]["hash"]
    username = user[0]["username"]
        
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
    
        # Ensure password was submitted    
        if not request.form.get("password"):
            return apology("must provide password", 400)
        
        # Ensure confirmation password was submitted    
        if not request.form.get("confirmation"):
            return apology("must provide confirmation password", 400)
        
        # Ensure new password is not same with the old one
        if request.form.get("password") == password:
            return apology("new password cannot be same with the old", 400)
            
        # Assing new password to the user
        db.execute("UPDATE users SET hash = ? WHERE id = ?", request.form.get("password"), session["user_id"])
        
        return redirect("/1")
        
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("account.html", username=username)
    

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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        
        # Ensure username exists and password is correct
        if len(rows) != 1 or rows[0]["hash"] != request.form.get("password"):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
        
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        
        # Ensure symbol is sumbitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)
        
        # Take inputs from quote.html
        symbol = request.form.get("symbol")
        
        # Ensure symbol is valid
        if lookup(symbol) == None:
            return apology("invalid symbol", 400)
            
        # Based on lookup function determine name and price of the stock symbol
        symbolDict = lookup(symbol)
        name = symbolDict["name"]
        price = symbolDict["price"]
        
        return render_template("quoted.html", name=name, price=price, symbol=symbol.upper())
        
    # User reached route via GET (as by clicking a link or via redirect) 
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)
        
        # Ensure password was submitted    
        if not request.form.get("password"):
            return apology("must provide password", 400)
        
        # Ensure confirmation password was submitted    
        if not request.form.get("confirmation"):
            return apology("must provide confirmation password", 400)
            
        # Take inputs from register.html    
        username = request.form.get("username")
        password = request.form.get("password")
        conpass = request.form.get("confirmation")
        
        # Query database for username
        users = db.execute("SELECT username FROM users")
        
        # Check whether username already exists or not
        for row in users:
            if username == row["username"]:
                return apology("username already exists", 400)
        
        # Check whether password and confirmation password is same        
        if password != conpass:
            return apology("passwords must match", 400)
        
        # Insert new users to users database
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, password)
    
        # Direct user to login page
        return redirect("/login")
    
    # User reached route via GET (as by clicking a link or via redirect)    
    else:    
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    
    # Find stocks that the user has owned
    historyStocks = db.execute("SELECT * FROM users_stock WHERE user_id = ?", session["user_id"])
    totalStocks = []
    
    for row in historyStocks:
        rowDict = {}
        symbolDict = lookup(row["symbol"])
        if symbolChecker(row["symbol"], totalStocks) == -1 and row["type"] == "buy":
            rowDict["symbol"] = row["symbol"]
            rowDict["name"] = symbolDict["name"]
            rowDict["price"] = symbolDict["price"]
            rowDict["share"] = row["shares"]
            rowDict["total"] = float("{:.2f}".format(float(row["shares"]) * symbolDict["price"]))
            
            totalStocks.append(rowDict)
            
        elif symbolChecker(row["symbol"], totalStocks) != -1 and row["type"] == "buy":
            rowN = symbolChecker(row["symbol"], totalStocks)
            totalStocks[rowN]["share"] += int(row["shares"])
            totalStocks[rowN]["total"] += float("{:.2f}".format(float(row["shares"]) * symbolDict["price"]))
        
        elif symbolChecker(row["symbol"], totalStocks) != -1 and row["type"] == "sell":
            rowN = symbolChecker(row["symbol"], totalStocks)
            totalStocks[rowN]["share"] += int(row["shares"])
            totalStocks[rowN]["total"] += float("{:.2f}".format(float(row["shares"]) * symbolDict["price"]))
            
            if totalStocks[rowN]["share"] == 0:
                del totalStocks[rowN]
                    
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        
        # Ensure symbol is sumbitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)
            
        # Ensure share is submitted
        if not request.form.get("shares"):
            return apology("must provide share", 400)
        
        # Take inputs from quote.html
        symbol = request.form.get("symbol")
                    
        # Ensure symbol is valid
        if lookup(symbol) == None or symbolChecker(symbol, totalStocks) == -1:
            return apology("invalid symbol", 400)
        
        # Declare share number
        share = request.form.get("shares")
        
        # Ensure share is valid
        if (int(share)*10) % 10 != 0 or int(share) <= 0:
            return apology("shares must be positive integer", 400)
        
        # Ensure the user has enough shares
        if not int(share) <= int(totalStocks[symbolChecker(symbol, totalStocks)]["share"]):
            return apology("shares are not enough")
            
        # Based on lookup function determine price of the stock symbol
        symbolDict = lookup(symbol)
        price = symbolDict["price"]
        
        # Find how much money the user has
        user = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        money = user[0]["cash"]
        
        db.execute("INSERT INTO users_stock (user_id, symbol, shares, price, type) VALUES(?, ?, ?, ?, ?)", 
                   session["user_id"], symbol.upper(), -int(share), price, "sell")
        
        money += float(share)*price
        
        db.execute("UPDATE users SET cash = ? WHERE id = ?", money, session["user_id"])
                    
        return redirect("/2")
        
    # User reached route via GET (as by clicking a link or via redirect) 
    else:
        return render_template("sell.html", stocks=totalStocks)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
