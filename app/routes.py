import csv
import random
from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify, abort, Response
from passlib.hash import sha256_crypt
from functools import wraps
import timeago
import itertools
import datetime
from flask_mail import Mail, Message
import plotly.graph_objects as go
from random import randint  # for generating random income
from datetime import date, timedelta
from datetime import datetime as dt
from flask_csv import send_csv
from flask import send_from_directory, make_response
from app import app
from app.forms import LoginForm, SignUpForm, TransactionForm, RequestResetForm, ResetPasswordForm
from app.__init__ import mysql, mail
from io import StringIO

@app.route('/')
def index():
    return render_template('/home.html')

@app.route('/change_currency/<new_currency>')
def change_currency(new_currency):
    try:
        # Other logic you might have
        session['current_currency'] = new_currency
        return redirect(url_for('dashboard'))
    except Exception as e:
        # Log the exception for debugging
        print(f"Error changing currency: {str(e)}")

        # Return an error response
        return jsonify(success=False, error=str(e)), 500

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm(request.form)
    if request.method == 'POST' and form.validate():
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        username = request.form['username']
        confirm = request.form['confirm']
        password = sha256_crypt.encrypt(str(request.form['password']))

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE email=%s", [email])
        if result > 0:
            flash('The entered email address has already been taken.Please try using or creating another one.', 'info')
            return redirect(url_for('signup'))
        else:
            cur.execute("INSERT INTO users(first_name, last_name, email, username, password) VALUES(%s, %s, %s, %s, %s)",
                        (first_name, last_name, email, username, password))
            mysql.connection.commit()
            cur.close()
            flash('You are now registered and can log in', 'success')
            return redirect(url_for('login'))
    return render_template('signUp.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = request.form['username']
        password_input = request.form['password']

        cur = mysql.connection.cursor()

        result = cur.execute(
            "SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            data = cur.fetchone()
            userID = data['id']
            password = data['password']
            role = data['role']

            if sha256_crypt.verify(password_input, password):
                session['logged_in'] = True
                session['username'] = username
                session['role'] = role
                session['userID'] = userID
                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid Password'
                return render_template('login.html', form=form, error=error)

            cur.close()

        else:
            error = 'Username not found'
            return render_template('login.html', form=form, error=error)

    return render_template('login.html', form=form)


def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Please login', 'info')
            return redirect(url_for('login'))
    return wrap


@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# Add Transactions


@app.route('/addTransactions', methods=['GET', 'POST'])
@is_logged_in
def add_transactions():
    if request.method == 'POST':
        amount = request.form['amount']
        description = request.form['description']
        category = request.form['category']

        # Form validation: Check if any of the required fields are empty
        if not amount or not description or not category:
            flash('Please fill in all fields.', 'danger')
        else:
            try:
                # Create a cursor and execute the SQL query
                with mysql.connection.cursor() as cur:
                    cur.execute(
                        "INSERT INTO transactions(user_id, amount, description, category, type) VALUES(%s, %s, %s, %s, %s)",
                        (session['userID'], amount, description, category, 'Daily Spend'))
                
                # Commit to the database
                mysql.connection.commit()

                flash('Transaction Successfully Recorded', 'success')

                return redirect(url_for('add_transactions'))
            except Exception as e:
                flash('An error occurred while recording the transaction. Please try again.', 'danger')
                # Log the exception for debugging purposes
                print(f"Error: {e}")

    # Fetch the total expenses for the current month
    with mysql.connection.cursor() as cur:
        cur.execute(
            "SELECT SUM(amount) FROM transactions WHERE MONTH(date) = MONTH(CURRENT_DATE()) AND YEAR(date) = YEAR(CURRENT_DATE()) AND user_id = %s",
            [session['userID']])
        data = cur.fetchone()
        total_expenses = data['SUM(amount)']

        # Fetch the transactions for the current month
        result = cur.execute(
            "SELECT * FROM transactions WHERE MONTH(date) = MONTH(CURRENT_DATE()) AND YEAR(date) = YEAR(CURRENT_DATE()) AND user_id = %s ORDER BY date DESC",
            [session['userID']]
        )

        transactions = []  # Initialize the transactions variable

        if result > 0:
            transactions = cur.fetchall()
            for transaction in transactions:
                if datetime.datetime.now() - transaction['date'] < datetime.timedelta(days=0.5):
                    transaction['date'] = timeago.format(
                        transaction['date'], datetime.datetime.now())
                else:
                    transaction['date'] = transaction['date'].strftime(
                        '%d %B, %Y')
            return render_template('addTransactions.html', totalExpenses=total_expenses, transactions=transactions, active_page='add')
        else:
            return render_template('addTransactions.html', result=result, active_page='add')

    return render_template('addTransactions.html')


@app.route('/transactionHistory', methods=['GET', 'POST'])
@is_logged_in
def transactionHistory():

    if request.method == 'POST':
        month = request.form['month']
        year = request.form['year']
        # Create cursor
        cur = mysql.connection.cursor()

        cur.execute(
            "SELECT SUM(amount) FROM transactions WHERE user_id = %s", [session['userID']])

        data = cur.fetchone()
        totalExpenses = data['SUM(amount)']

        if month == "00":
            cur.execute(
                f"SELECT SUM(amount) FROM transactions WHERE YEAR(date) = YEAR('{year}-00-00') AND user_id = {session['userID']}")

            data = cur.fetchone()
            totalExpenses = data['SUM(amount)']

            result = cur.execute(
                f"SELECT * FROM transactions WHERE YEAR(date) = YEAR('{year}-00-00') AND user_id = {session['userID']} ORDER BY date DESC")
        else:

            cur.execute(
                f"SELECT SUM(amount) FROM transactions WHERE MONTH(date) = MONTH('0000-{month}-00') AND YEAR(date) = YEAR('{year}-00-00') AND user_id = {session['userID']}")

            data = cur.fetchone()
            totalExpenses = data['SUM(amount)']

            result = cur.execute(
                f"SELECT * FROM transactions WHERE MONTH(date) = MONTH('0000-{month}-00') AND YEAR(date) = YEAR('{year}-00-00') AND user_id = {session['userID']} ORDER BY date DESC")

        if result > 0:
            transactions = cur.fetchall()
            for transaction in transactions:
                transaction['date'] = transaction['date'].strftime(
                    '%d %B, %Y')
            return render_template('transactionHistory.html', totalExpenses=totalExpenses, transactions=transactions)
        else:
            cur.execute(f"SELECT MONTHNAME('0000-{month}-00')")
            data = cur.fetchone()
            if month != "00":
                monthName = data[f'MONTHNAME(\'0000-{month}-00\')']
                msg = f"No Transactions Found For {monthName}, {year}"
            else:
                msg = f"No Transactions Found For {year}"
            return render_template('transactionHistory.html', result=result, msg=msg)
        # Close connection
        cur.close()
    else:
        # Create cursor
        cur = mysql.connection.cursor()

        cur.execute(
            "SELECT SUM(amount) FROM transactions WHERE user_id = %s", [session['userID']])

        data = cur.fetchone()
        totalExpenses = data['SUM(amount)']

        # Get Latest Transactions made by a particular user
        result = cur.execute(
            "SELECT * FROM transactions WHERE user_id = %s ORDER BY date DESC", [
                session['userID']]
        )

        if result > 0:
            transactions = cur.fetchall()
            for transaction in transactions:
                transaction['date'] = transaction['date'].strftime(
                    '%d %B, %Y')
            return render_template('transactionHistory.html', totalExpenses=totalExpenses, transactions=transactions, active_page='history')
        else:
            flash('No Transactions Found', 'success')
            return redirect(url_for('add_transactions'))
        # Close connection
        cur.close()


@app.route('/editTransaction/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def editTransaction(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Get transaction by id
    cur.execute("SELECT * FROM transactions WHERE id = %s", [id])

    transaction = cur.fetchone()
    cur.close()
    # Get form
    form = TransactionForm(request.form)

    # Populate transaction form fields
    form.amount.data = transaction['amount']
    form.description.data = transaction['description']

    if request.method == 'POST' and form.validate():
        amount = request.form['amount']
        description = request.form['description']

        # Create Cursor
        cur = mysql.connection.cursor()
        # Execute
        cur.execute("UPDATE transactions SET amount=%s, description=%s WHERE id = %s",
                    (amount, description, id))
        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('Transaction Updated', 'success')

        return redirect(url_for('transactionHistory'))

    return render_template('editTransaction.html', form=form, active_page='add')

# Delete transaction


@app.route('/deleteTransaction/<string:id>', methods=['POST'])
@is_logged_in
def deleteTransaction(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("DELETE FROM transactions WHERE id = %s", [id])

    # Commit to DB
    mysql.connection.commit()

    # Close connection
    cur.close()

    flash('Transaction Deleted', 'success')

    return redirect(url_for('transactionHistory'))


@app.route('/editCurrentMonthTransaction/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def editCurrentMonthTransaction(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Get transaction by id
    cur.execute("SELECT * FROM transactions WHERE id = %s", [id])

    transaction = cur.fetchone()
    cur.close()
    # Get form
    form = TransactionForm(request.form)

    # Populate transaction form fields
    form.amount.data = transaction['amount']
    form.description.data = transaction['description']

    if request.method == 'POST' and form.validate():
        amount = request.form['amount']
        description = request.form['description']

        # Create Cursor
        cur = mysql.connection.cursor()
        # Execute
        cur.execute("UPDATE transactions SET amount=%s, description=%s WHERE id = %s",
                    (amount, description, id))
        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('Transaction Updated', 'success')

        return redirect(url_for('add_transactions'))

    return render_template('editTransaction.html', form=form)

# Delete transaction


@app.route('/deleteCurrentMonthTransaction/<string:id>', methods=['POST'])
@is_logged_in
def deleteCurrentMonthTransaction(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("DELETE FROM transactions WHERE id = %s", [id])

    # Commit to DB
    mysql.connection.commit()

    # Close connection
    cur.close()

    flash('Transaction Deleted', 'success')

    return redirect(url_for('dashboard'))


@app.route("/reset_request", methods=['GET', 'POST'])
def reset_request():
    if 'logged_in' in session and session['logged_in'] == True:
        flash('You are already logged in', 'info')
        return redirect(url_for('index'))
    form = RequestResetForm(request.form)
    if request.method == 'POST' and form.validate():
        email = form.email.data
        cur = mysql.connection.cursor()
        result = cur.execute(
            "SELECT id,username,email FROM users WHERE email = %s", [email])
        if result == 0:
            flash(
                'There is no account with that email. You must register first.', 'warning')
            return redirect(url_for('signup'))
        else:
            data = cur.fetchone()
            user_id = data['id']
            user_email = data['email']
            cur.close()
            s = Serializer(app.config['SECRET_KEY'], 1800)
            token = s.dumps({'user_id': user_id}).decode('utf-8')
            msg = Message('Password Reset Request',
                          sender='noreply@demo.com', recipients=[user_email])
            msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make password reset request then simply ignore this email and no changes will be made.
Note:This link is valid only for 30 mins from the time you requested a password change request.
'''
            mail.send(msg)
            flash(
                'An email has been sent with instructions to reset your password.', 'info')
            return redirect(url_for('login'))
    return render_template('reset_request.html', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if 'logged_in' in session and session['logged_in'] == True:
        flash('You are already logged in', 'info')
        return redirect(url_for('index'))
    s = Serializer(app.config['SECRET_KEY'])
    try:
        user_id = s.loads(token)['user_id']
    except:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM users WHERE id = %s", [user_id])
    data = cur.fetchone()
    cur.close()
    user_id = data['id']
    form = ResetPasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        password = sha256_crypt.encrypt(str(form.password.data))
        cur = mysql.connection.cursor()
        cur.execute(
            "UPDATE users SET password = %s WHERE id = %s", (password, user_id))
        mysql.connection.commit()
        cur.close()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)


@app.route('/category')
def createBarCharts():
    cur = mysql.connection.cursor()
    result = cur.execute(
        f"SELECT Sum(amount) AS amount, category FROM transactions WHERE YEAR(date) = YEAR(CURRENT_DATE()) AND user_id = {session['userID']} GROUP BY category ORDER BY category")
    if result > 0:
        transactions = cur.fetchall()
        values = []
        labels = []
        for transaction in transactions:
            values.append(transaction['amount'])
            labels.append(transaction['category'])

        fig = go.Figure(data=[go.Pie(labels=labels, values=values)])
        fig.update_traces(textinfo='label+value', hoverinfo='percent')
        fig.update_layout(
            title_text='Category Wise Pie Chart For Current Year')
        fig.show()
    cur.close()
    return redirect(url_for('add_transactions'))

# Comparison Between Current and Previous Year #


@app.route('/yearly_bar')
def yearlyBar():
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('01', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        a1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('01', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        a2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('02', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        b1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('02', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        b2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('03', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        c1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('03', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        c2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('04', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        d1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('04', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        d2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('05', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        e1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('05', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        e2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('06', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        f1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('06', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        f2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('07', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        g1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('07', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        g2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('08', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        h1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('08', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        h2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('09', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        i1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('09', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        i2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('10', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        j1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('10', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        j2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('11', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        k1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('11', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        k2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('12', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        l1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('12', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        l2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE  YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ([
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        m1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM transactions WHERE YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ([
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        m2 = data['Sum(amount)']

    year = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'June',
            'July', 'Aug', 'Sept', 'Oct', 'Nov', 'Dec', 'Total']
    fig = go.Figure(data=[
        go.Bar(name='Last Year', x=year, y=[
               a2, b2, c2, d2, e2, f2, g2, h2, i2, j2, k2, l2, m2]),
        go.Bar(name='This Year', x=year, y=[
               a1, b1, c1, d1, e1, f1, g1, h1, i1, j1, k1, l1, m1])
    ])
    fig.update_layout(
        barmode='group', title_text='Comparison Between This Year and Last Year')
    fig.show()
    return redirect(url_for('add_transactions'))

# Current Year Month Wise #


@app.route('/monthly_bar')
def monthlyBar():
    cur = mysql.connection.cursor()
    result = cur.execute(
        f"SELECT sum(amount) as amount, month(date) FROM transactions WHERE YEAR(date) = YEAR(CURRENT_DATE()) AND user_id = {session['userID']} GROUP BY MONTH(date) ORDER BY MONTH(date)")
    if result > 0:
        transactions = cur.fetchall()
        year = []
        value = []
        for transaction in transactions:
            year.append(transaction['month(date)'])
            value.append(transaction['amount'])

        fig = go.Figure([go.Bar(x=year, y=value)])
        fig.update_layout(title_text='Monthly Bar Chart For Current Year')
        fig.show()
    cur.close()
    return redirect(url_for('add_transactions'))

@app.route('/daily_line_chart')
def daily_line_chart():
    cur = mysql.connection.cursor()
    result = cur.execute(
        f"SELECT sum(amount) as amount, date FROM transactions WHERE user_id = {session['userID']} GROUP BY date ORDER BY date")
    if result > 0:
        transactions = cur.fetchall()
        date = []
        value = []
        for transaction in transactions:
            date.append(transaction['date'])
            value.append(transaction['amount'])

        fig = go.Figure([go.Bar(x=date, y=value)])
        fig.update_layout(title_text='Daily Line Chart For Current Year')
        fig.show()
    cur.close()
    return redirect(url_for('add_transactions'))

@app.route('/income', methods=['GET', 'POST'])
@is_logged_in
def addIncome():
    if request.method == 'POST':
        amount = request.form['amount']
        description = request.form['description']
        source = request.form['source']

        if not amount or not description or not source:
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('addIncome'))

        # Create Cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute(
            "INSERT INTO income(user_id, amount, description, source) VALUES(%s, %s, %s, %s)",
            (session['userID'], amount, description, source)
        )

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('Income Successfully Recorded', 'success')

        return redirect(url_for('addIncome'))

    else:
        cur = mysql.connection.cursor()

        cur.execute(
            "SELECT SUM(amount) FROM income WHERE MONTH(date) = MONTH(CURRENT_DATE()) AND YEAR(date) = YEAR(CURRENT_DATE()) AND user_id = %s", [session['userID']]
        )

        data = cur.fetchone()
        totalIncome = data['SUM(amount)']

        # get the month's income made by a particular user
        result = cur.execute(
            "SELECT * FROM income WHERE MONTH(date) = MONTH(CURRENT_DATE()) AND YEAR(date) = YEAR(CURRENT_DATE()) AND user_id = %s ORDER BY date DESC", [session['userID']]
        )

        if result > 0:
            incomes = cur.fetchall()
            for income in incomes:
                if datetime.datetime.now() - income['date'] < datetime.timedelta(days=0.5):
                    income['date'] = timeago.format(
                        income['date'], datetime.datetime.now())
                else:
                    income['date'] = income['date'].strftime(
                        '%d %B, %Y')
            return render_template('income.html', totalIncome=totalIncome, incomes=incomes, active_page='income')
        else:
            return render_template('income.html', result=result, active_page='income')
        
        

        # close the connections
        cur.close()
    return render_template('income.html')

@app.route('/editIncome/<int:income_id>', methods=['GET', 'POST'])
@is_logged_in
def editIncome(income_id):
    cur = mysql.connection.cursor()

    # Fetch the income to edit
    result = cur.execute("SELECT * FROM income WHERE id = %s", [income_id])

    if result > 0:
        income = cur.fetchone()

        if request.method == 'POST':
            amount = request.form['amount']
            description = request.form['description']
            source = request.form['source']

            # Update the income
            cur.execute(
                "UPDATE income SET amount=%s, description=%s, source=%s WHERE id=%s",
                (amount, description, source, income_id)
            )

            # Commit to DB
            mysql.connection.commit()

            # Close connection
            cur.close()

            flash('Income Updated Successfully', 'success')

            # Redirect to the 'income' page
            return redirect(url_for('addIncome'))

        return render_template('editIncome.html', income=income)
    else:
        flash('Income not found', 'danger')
        return redirect(url_for('dashboard'))


# Delete Income
@app.route('/deleteIncome/<int:income_id>', methods=['POST'])
@is_logged_in
def deleteIncome(income_id):
    cur = mysql.connection.cursor()

    # Fetch the income to delete
    result = cur.execute("SELECT * FROM income WHERE id = %s", [income_id])

    if result > 0:
        # Delete the income
        cur.execute("DELETE FROM income WHERE id = %s", [income_id])

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('Income Deleted Successfully', 'success')

    else:
        flash('Income not found', 'danger')

    return redirect(url_for('addIncome'))

@app.route('/category_income')
def createBarChartsIncome():
    cur = mysql.connection.cursor()
    result = cur.execute(
        f"SELECT Sum(amount) AS amount, source FROM income WHERE YEAR(date) = YEAR(CURRENT_DATE()) AND user_id = {session['userID']} GROUP BY source ORDER BY source")
    if result > 0:
        transactions = cur.fetchall()
        values = []
        labels = []
        for transaction in transactions:
            values.append(transaction['amount'])
            labels.append(transaction['source'])

        fig = go.Figure(data=[go.Pie(labels=labels, values=values)])
        fig.update_traces(textinfo='label+value', hoverinfo='percent')
        fig.update_layout(
            title_text='Category Wise Pie Chart For Current Year')
        fig.show()
    cur.close()
    return redirect(url_for('addIncome'))

@app.route('/yearly_bar_income')
def yearlyBarIncome():
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('01', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        a1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('01', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        a2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('02', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        b1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('02', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        b2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('03', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        c1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('03', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        c2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('04', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        d1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('04', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        d2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('05', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        e1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('05', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        e2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('06', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        f1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('06', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        f2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('07', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        g1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('07', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        g2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('08', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        h1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('08', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        h2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('09', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        i1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('09', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        i2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('10', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        j1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('10', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        j2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('11', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        k1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('11', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        k2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ('12', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        l1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE MONTH(date) = %s  AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ('12', [
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        l2 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE  YEAR(date) = YEAR(CURRENT_DATE())  AND user_id = %s", ([
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        m1 = data['Sum(amount)']
    result = cur.execute("SELECT Sum(amount) FROM income WHERE YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR))  AND user_id = %s", ([
        session['userID']]))
    if result > 0:
        data = cur.fetchone()
        m2 = data['Sum(amount)']

    year = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'June',
            'July', 'Aug', 'Sept', 'Oct', 'Nov', 'Dec', 'Total']
    fig = go.Figure(data=[
        go.Bar(name='Last Year', x=year, y=[
               a2, b2, c2, d2, e2, f2, g2, h2, i2, j2, k2, l2, m2]),
        go.Bar(name='This Year', x=year, y=[
               a1, b1, c1, d1, e1, f1, g1, h1, i1, j1, k1, l1, m1])
    ])
    fig.update_layout(
        barmode='group', title_text='Comparison Between This Year and Last Year')
    fig.show()
    return redirect(url_for('addIncome'))

# Current Year Month Wise #


@app.route('/monthly_bar_income')
def monthlyBarIncome():
    cur = mysql.connection.cursor()
    result = cur.execute(
        f"SELECT sum(amount) as amount, month(date) FROM income WHERE YEAR(date) = YEAR(CURRENT_DATE()) AND user_id = {session['userID']} GROUP BY MONTH(date) ORDER BY MONTH(date)")
    if result > 0:
        transactions = cur.fetchall()
        year = []
        value = []
        for transaction in transactions:
            year.append(transaction['month(date)'])
            value.append(transaction['amount'])

        fig = go.Figure([go.Bar(x=year, y=value)])
        fig.update_layout(title_text='Monthly Bar Chart For Current Year')
        fig.show()
    cur.close()
    return redirect(url_for('addIncome'))

@app.route('/bill', methods=['GET', 'POST'])
@is_logged_in
def addBill():
    if request.method == 'POST':
        amount = request.form['amount']
        description = request.form['description']
        category = request.form['category']
        expiration_date = request.form['expiration_date']
        paid = request.form['paid']

        # Validate form data
        if not amount or not description or not category or not expiration_date:
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('addBill'))

        # Create Cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute(
            "INSERT INTO bills(user_id, amount, description, category, expiration_date, paid) VALUES(%s, %s, %s, %s, %s, %s)",
            (session['userID'], amount, description, category, expiration_date, paid)  # 0 for 'NO'
        )

        if paid == '1':
            cur.execute("""INSERT INTO transactions (user_id, category, amount, description, type)
                VALUES (%s, %s, %s, %s, %s)""", (session['userID'], category, amount, description, 'Bill'))
        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('Bill Successfully Recorded', 'success')

        return redirect(url_for('addBill'))

    else:
        # Fetch bills data for display
        cur = mysql.connection.cursor()

        # Fetch total amount of bills
        cur.execute(
            "SELECT SUM(amount) FROM bills WHERE user_id = %s", [session['userID']]
        )
        data = cur.fetchone()
        totalBill = data['SUM(amount)']

        # Fetch all bills with formatted date and paid status
        cur.execute(
            "SELECT *, DATE_FORMAT(expiration_date, '%%d-%%m-%%Y') as formatted_date, CASE WHEN paid = 1 THEN 'Yes' ELSE 'No' END as paid_status FROM bills WHERE user_id = %s ORDER BY expiration_date DESC", [session['userID']]
        )
        result = cur.fetchall()
        # Identify bills with upcoming expirations and unpaid status
        upcoming_unpaid_bills = []
        for bill in result:
            expiration_date = bill['expiration_date']
            paid = bill['paid']

            if paid == 0:  # Check if paid is 0 (No) in the database
                current_date = datetime.datetime.now()
                two_days_before_expiration = expiration_date - datetime.timedelta(days=2)

                # Check if it's 10:33 PM, two days before expiration
                if current_date.hour == 22 and current_date.minute == 36 and current_date >= two_days_before_expiration:
                    flash_message = f'You have to pay in 2 days for bill with description: "{bill["description"]}", thank you.'
                    flash(flash_message, 'warning')

        return render_template('bills.html', bills=result, totalBill=totalBill, active_page='bill')
    

@app.route('/complete_bill/<int:bill_id>', methods=['POST'])
@is_logged_in
def complete_bill(bill_id):
    if request.method == 'POST':
        cur = mysql.connection.cursor()

        # Fetch the bill to complete
        result = cur.execute("SELECT * FROM bills WHERE id = %s", [bill_id])

        if result > 0:
            bill = cur.fetchone()

            # Insert the bill data into transactions table
            cur.execute("""
                INSERT INTO transactions (user_id, category, amount, description, type)
                VALUES (%s, %s, %s, %s, %s)
            """, (bill['user_id'], bill['category'], bill['amount'], bill['description'], 'bill'))

            # Commit to DB
            mysql.connection.commit()

            # Update the bill status to 'complete'
            cur.execute("UPDATE bills SET paid = '1' WHERE id = %s", [bill_id])

            # Commit to DB
            mysql.connection.commit()

            # Close connection
            cur.close()

            flash('bill Completed Successfully', 'success')
        else:
            flash('bill not found', 'danger')

    return redirect(url_for('addBill'))
# Edit Bill
@app.route('/editBill/<int:bill_id>', methods=['GET', 'POST'])
@is_logged_in
def editBill(bill_id):
    cur = mysql.connection.cursor()

    # Fetch the bill to edit
    result = cur.execute("SELECT * FROM bills WHERE id = %s", [bill_id])

    if result > 0:
        bill = cur.fetchone()

        if request.method == 'POST':
            amount = request.form['amount']
            description = request.form['description']
            category = request.form['category']
            expiration_date = request.form['expiration_date']
            paid = int(request.form['paid'])  # Convert 'Yes'/'No' to 1/0

            # Update the bill
            cur.execute(
                "UPDATE bills SET amount=%s, description=%s, category=%s, expiration_date=%s, paid=%s WHERE id=%s",
                (amount, description, category, expiration_date, paid, bill_id)
            )

            # Commit to DB
            mysql.connection.commit()

            # Close connection
            cur.close()

            flash('Bill Updated Successfully', 'success')

            # Redirect to the 'bills' page
            return redirect(url_for('addBill'))

        return render_template('editBill.html', bill=bill)
    else:
        flash('Bill not found', 'danger')
        return redirect(url_for('addBill'))


# Delete Bill
@app.route('/deleteBill/<int:bill_id>', methods=['POST'])
@is_logged_in
def deleteBill(bill_id):
    cur = mysql.connection.cursor()

    # Fetch the bill to delete
    result = cur.execute("SELECT * FROM bills WHERE id = %s", [bill_id])

    if result > 0:
        # Delete the bill
        cur.execute("DELETE FROM bills WHERE id = %s", [bill_id])

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('Bill Deleted Successfully', 'success')

    else:
        flash('Bill not found', 'danger')

    return redirect(url_for('addBill'))



@app.route('/category_bill')
def createBarChartsBill():
    cur = mysql.connection.cursor()
    result = cur.execute(
        f"SELECT Sum(amount) AS amount, category FROM bills WHERE YEAR(expiration_date) = YEAR(CURRENT_DATE()) AND user_id = {session['userID']} GROUP BY category ORDER BY category")
    if result > 0:
        transactions = cur.fetchall()
        values = []
        labels = []
        for transaction in transactions:
            values.append(transaction['amount'])
            labels.append(transaction['category'])

        fig = go.Figure(data=[go.Pie(labels=labels, values=values)])
        fig.update_traces(textinfo='label+value', hoverinfo='percent')
        fig.update_layout(
            title_text='Category Wise Pie Chart For Current Year')
        fig.show()
    cur.close()
    return redirect(url_for('addBill'))

@app.route('/yearly_bar_bill')
def yearlyBarBill():
    cur = mysql.connection.cursor()

    # Define the months and initialize lists to store the sums
    months = ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12']
    this_year_sums = []
    last_year_sums = []

    # Loop through months
    for month in months:
        # This year
        result = cur.execute("SELECT SUM(amount) FROM bills WHERE MONTH(expiration_date) = %s AND YEAR(expiration_date) = YEAR(CURRENT_DATE()) AND user_id = %s", (month, session['userID']))
        if result > 0:
            data = cur.fetchone()
            this_year_sums.append(data['SUM(amount)'])
        else:
            this_year_sums.append(0)

        # Last year
        result = cur.execute("SELECT SUM(amount) FROM bills WHERE MONTH(expiration_date) = %s AND YEAR(expiration_date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR)) AND user_id = %s", (month, session['userID']))
        if result > 0:
            data = cur.fetchone()
            last_year_sums.append(data['SUM(amount)'])
        else:
            last_year_sums.append(0)

    # Total for each year
    result = cur.execute("SELECT SUM(amount) FROM bills WHERE YEAR(expiration_date) = YEAR(CURRENT_DATE()) AND user_id = %s", (session['userID'],))
    if result > 0:
        data = cur.fetchone()
        this_year_total = data['SUM(amount)']
    else:
        this_year_total = 0

    result = cur.execute("SELECT SUM(amount) FROM bills WHERE YEAR(expiration_date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR)) AND user_id = %s", (session['userID'],))
    if result > 0:
        data = cur.fetchone()
        last_year_total = data['SUM(amount)']
    else:
        last_year_total = 0

    # Add total to the lists
    this_year_sums.append(this_year_total)
    last_year_sums.append(last_year_total)

    # Create the bar chart
    fig = go.Figure(data=[
        go.Bar(name='Last Year', x=months + ['Total'], y=last_year_sums),
        go.Bar(name='This Year', x=months + ['Total'], y=this_year_sums)
    ])

    fig.update_layout(
        barmode='group', title_text='Comparison Between This Year and Last Year'
    )

    fig.show()
    cur.close()

    return redirect(url_for('addBill'))

# Current Year Month Wise #


@app.route('/monthly_bar_bill')
def monthlyBarBill():
    cur = mysql.connection.cursor()
    result = cur.execute(
        f"SELECT sum(amount) as amount, month(expiration_date) FROM bills WHERE YEAR(expiration_date) = YEAR(CURRENT_DATE()) AND user_id = {session['userID']} GROUP BY MONTH(expiration_date) ORDER BY MONTH(expiration_date)")
    if result > 0:
        transactions = cur.fetchall()
        year = []
        value = []
        for transaction in transactions:
            year.append(transaction['month(expiration_date)'])
            value.append(transaction['amount'])

        fig = go.Figure([go.Bar(x=year, y=value)])
        fig.update_layout(title_text='Monthly Bar Chart For Current Year')
        fig.show()
    cur.close()
    return redirect(url_for('addBill'))

@app.route('/dashboard')
@is_logged_in
def dashboard():
    # Extract user_id from the current user
    user_id = session.get('userID')

    today = date.today()
    start_of_month = date(today.year, today.month, 1)
    if today.month == 12:
        end_of_month = date(today.year + 1, 1, 1) - timedelta(days=1)
    else:
        end_of_month = date(today.year, today.month + 1, 1) - timedelta(days=1)

    # Fetch today's expense from MySQL
    
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT 
            SUM(amount) AS today_expense 
        FROM transactions 
        WHERE user_id = %s 
            AND DATE(date) = %s
    """, (user_id, today))
    today_expense_data = cur.fetchone()
    
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT 
            SUM(amount) AS total_expense 
        FROM transactions 
        WHERE user_id = %s
    """, (user_id,))
    total_expense_data = cur.fetchone()
    total_expense = total_expense_data['total_expense']

    cur.execute("""
        SELECT 
            SUM(amount) AS total_income 
        FROM income
        WHERE user_id = %s
    """, (user_id,))
    total_income_data = cur.fetchone()
    total_income = total_income_data['total_income']


    cur.execute("""
        SELECT 
            SUM(amount) AS month_bill 
        FROM transactions 
        WHERE user_id = %s 
            AND DATE(date) BETWEEN %s AND %s
            AND type = 'bill'
    """, (user_id, start_of_month, end_of_month))
    this_month_bill_data = cur.fetchone()

    cur.execute("""
    SELECT 
            SUM(amount) AS total_bills 
        FROM transactions 
        WHERE user_id = %s 
            AND type = 'bill'
    """, (user_id,))
    total_bill_data = cur.fetchone()


    # Fetch this month's expense from MySQL
    start_of_month = date(today.year, today.month, 1)
    if today.month == 12:
        end_of_month = date(today.year + 1, 1, 1) - timedelta(days=1)
    else:
        end_of_month = date(today.year, today.month + 1, 1) - timedelta(days=1)

    cur.execute("""
        SELECT 
            SUM(amount) AS month_expense 
        FROM transactions 
        WHERE user_id = %s 
            AND DATE(date) BETWEEN %s AND %s
    """, (user_id, start_of_month, end_of_month))
    this_month_expense_data = cur.fetchone()

    cur.execute("""
        SELECT 
            SUM(amount) AS month_income 
        FROM income
        WHERE user_id = %s 
            AND DATE(date) BETWEEN %s AND %s
    """, (user_id, start_of_month, end_of_month))
    this_month_income_data = cur.fetchone()

    # Fetch this month's most spending category from MySQL
    cur.execute("""
        SELECT 
            category, 
            SUM(amount) AS total_amount
        FROM transactions 
        WHERE user_id = %s 
            AND DATE(date) BETWEEN %s AND %s
        GROUP BY category
        ORDER BY total_amount DESC
        LIMIT 1
    """, (user_id, start_of_month, end_of_month))

    most_spending_category = cur.fetchone()
    # Fetch expense data from MySQL
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT 
            category, 
            SUM(amount) AS total_expense 
        FROM transactions 
        WHERE user_id = %s 
        AND MONTH(date) = MONTH(CURRENT_DATE())
        GROUP BY category
    """, (user_id,))
    category_data = cur.fetchall()

    current_year = datetime.datetime.now().year

    # Fetch expense data from MySQL
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT 
            COALESCE(MONTH(STR_TO_DATE(date, '%%Y-%%m-%%d %%H:%%i:%%s')), 0) AS month, 
            IFNULL(SUM(amount), 0) AS total_expense 
        FROM transactions 
        WHERE user_id = %s AND YEAR(STR_TO_DATE(date, '%%Y-%%m-%%d %%H:%%i:%%s')) = %s
        GROUP BY month
    """, (user_id, current_year))
    expense_data = cur.fetchall()

    # Fetch expense data from MySQL
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT 
            COALESCE(MONTH(STR_TO_DATE(date, '%%Y-%%m-%%d %%H:%%i:%%s')), 0) AS month, 
            IFNULL(SUM(amount), 0) AS total_income
        FROM income
        WHERE user_id = %s AND YEAR(STR_TO_DATE(date, '%%Y-%%m-%%d %%H:%%i:%%s')) = %s
        GROUP BY month
    """, (user_id, current_year))
    income_data = cur.fetchall()
    
    # Create cursor
    cur = mysql.connection.cursor()

    cur.execute(
        "SELECT SUM(amount) FROM transactions WHERE user_id = %s", [session['userID']])

    data = cur.fetchone()
    totalExpenses = data['SUM(amount)']
    transactions = []   
    # Get Latest Transactions made by a particular user
    result = cur.execute(
        "SELECT * FROM transactions WHERE user_id = %s ORDER BY date DESC", [
            session['userID']]
    )

    if result > 0:
        transactions = cur.fetchall()
        for transaction in transactions:
            transaction['date'] = transaction['date'].strftime(
                '%d %B, %Y')
    # Pass data to the template
    return render_template('dashboard.html',totalExpenses=totalExpenses, transactions=transactions, active_page='dashboard', category_data=category_data, most_spending_category=most_spending_category, today_expense_data=today_expense_data, this_month_expense_data=this_month_expense_data, this_month_income_data=this_month_income_data,  expense_data=expense_data, income_data=income_data,
                           total_expense=total_expense, total_income=total_income, this_month_bill_data=this_month_bill_data, total_bill=total_bill_data)


@app.route('/goal', methods=['GET', 'POST'])
@is_logged_in
def addGoal():
    if request.method == 'POST':
        amount = request.form['amount']
        description = request.form['description']
        category = request.form['category']
        priority = request.form['priority']
        target_date = request.form['target_date']

        target_date = dt.strptime(request.form['target_date'], '%Y-%m-%d')
        tomorrow = dt.now() + timedelta(days=1)

        if target_date <= tomorrow:
            flash('Target Date must be tomorrow or later.', 'danger')
            return redirect(url_for('addGoal'))
        
        # Create Cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute(
            "INSERT INTO goal(user_id, amount, description, category, priority, target_date, status) VALUES(%s, %s, %s, %s, %s, %s, %s)",
            (session['userID'], amount, description, category, priority, target_date, 'Incomplete')
        )

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('Goal Successfully Recorded', 'success')

        return redirect(url_for('addGoal'))

    else:
        cur = mysql.connection.cursor()

        cur.execute(
            "SELECT SUM(amount) FROM goal WHERE user_id = %s", [session['userID']]
        )

        data = cur.fetchone()
        totalGoalAmount = data['SUM(amount)']

        # get the month's goals made by a particular user
        result = cur.execute(
            "SELECT * FROM goal WHERE user_id = %s ORDER BY target_date DESC", [session['userID']]
        )

        if result > 0:
            goals = cur.fetchall()
            return render_template('goal.html', totalGoalAmount=totalGoalAmount, goals=goals, active_page='goal')
        else:
            return render_template('goal.html', result=result, active_page='goal')

        # close the connections
        cur.close()
    return render_template('goal.html')


@app.route('/complete_goal/<int:goal_id>', methods=['POST'])
@is_logged_in
def complete_goal(goal_id):
    if request.method == 'POST':
        cur = mysql.connection.cursor()

        # Fetch the goal to complete
        result = cur.execute("SELECT * FROM goal WHERE id = %s", [goal_id])

        if result > 0:
            goal = cur.fetchone()

            # Insert the goal data into transactions table
            cur.execute("""
                INSERT INTO transactions (user_id, category, amount, description, type)
                VALUES (%s, %s, %s, %s, %s)
            """, (goal['user_id'], goal['category'], goal['amount'], goal['description'], 'Goal'))

            # Commit to DB
            mysql.connection.commit()

            # Update the goal status to 'complete'
            cur.execute("UPDATE goal SET status = 'Complete' WHERE id = %s", [goal_id])

            # Commit to DB
            mysql.connection.commit()

            # Close connection
            cur.close()

            flash('Goal Completed Successfully', 'success')
        else:
            flash('Goal not found', 'danger')

    return redirect(url_for('addGoal'))


@app.route('/editGoal/<int:goal_id>', methods=['GET', 'POST'])
@is_logged_in
def editGoal(goal_id):
    cur = mysql.connection.cursor()

    # Fetch the goal to edit
    result = cur.execute("SELECT * FROM goal WHERE id = %s", [goal_id])

    if result > 0:
        goal = cur.fetchone()

        if request.method == 'POST':
            amount = request.form['amount']
            description = request.form['description']
            category = request.form['category']
            priority = request.form['priority']
            target_date = request.form['target_date']

            # Update the goal
            cur.execute(
                "UPDATE goal SET amount=%s, description=%s, category=%s, priority=%s, target_date=%s WHERE id=%s",
                (amount, description, category, priority, target_date, goal_id)
            )

            # Commit to DB
            mysql.connection.commit()

            # Close connection
            cur.close()

            flash('Goal Updated Successfully', 'success')

            # Redirect to the 'goal' page
            return redirect(url_for('addGoal'))

        return render_template('editGoal.html', goal=goal)
    else:
        flash('Goal not found', 'danger')
        return redirect(url_for('dashboard'))

# Delete Goal
@app.route('/deleteGoal/<int:goal_id>', methods=['POST'])
@is_logged_in
def deleteGoal(goal_id):
    cur = mysql.connection.cursor()

    # Fetch the goal to delete
    result = cur.execute("SELECT * FROM goal WHERE id = %s", [goal_id])

    if result > 0:
        # Delete the goal
        cur.execute("DELETE FROM goal WHERE id = %s", [goal_id])

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('Goal Deleted Successfully', 'success')

    else:
        flash('Goal not found', 'danger')

    return redirect(url_for('addGoal'))


@app.route('/adminDashboard')
@is_logged_in  # Assuming you have this decorator for general user authentication
def admin_dashboard():
    if session.get('role') != 'admin':
        abort(403)  # Forbidden, or you can redirect to another page

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users")
    
    users_data = cur.fetchall()  # Fetch all users

    # Dummy data for demonstration purposes
    total_entries = len(users_data)
    items_per_page = 10
    total_pages = -(-total_entries // items_per_page)  # Calculate total pages

    current_page = 1  # Set the current page (you should adjust this based on user input or session)

    # Calculate the start and end indices for pagination
    start_idx = (current_page - 1) * items_per_page
    end_idx = start_idx + items_per_page

    # Slice the users_data list based on the current page
    users_data_page = users_data[start_idx:end_idx]

    return render_template('admin_dashboard.html', users=users_data_page, total_entries=total_entries,
                           total_pages=total_pages, current_page=current_page, active_page='admin_dashboard')

# Edit User
@app.route('/editUser/<int:user_id>', methods=['GET', 'POST'])
@is_logged_in
def editUser(user_id):
    cur = mysql.connection.cursor()

    # Fetch the user to edit
    result = cur.execute("SELECT * FROM users WHERE id = %s", [user_id])

    if result > 0:
        user = cur.fetchone()

        if request.method == 'POST':
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            email = request.form['email']
            role = request.form['role']
            # status = request.form['status']

            # Update the user (excluding the role field)
            # Update the user
            cur.execute(
                "UPDATE users SET first_name=%s, last_name=%s, email=%s, role=%s WHERE id=%s",
                (request.form['first_name'], request.form['last_name'], request.form['email'], request.form['role'], user_id)
            )
            # Commit to DB
            mysql.connection.commit()

            # Close connection
            cur.close()

            flash('User Updated Successfully', 'success')

            # Redirect to the 'admin_dashboard' page
            return redirect(url_for('admin_dashboard'))

        return render_template('editUser.html', user=user)
    else:
        flash('User not found', 'danger')
        return redirect(url_for('admin_dashboard'))
    
# Delete User
@app.route('/deleteUser/<int:user_id>', methods=['POST'])
@is_logged_in
def deleteUser(user_id):
    cur = mysql.connection.cursor()

    # Check if the user exists
    result = cur.execute("SELECT * FROM users WHERE id = %s", [user_id])

    if result > 0:
        # Delete the user
        cur.execute("DELETE FROM users WHERE id = %s", [user_id])

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('User Deleted Successfully', 'success')

    else:
        flash('User not found', 'danger')

    # Redirect to the 'admin_dashboard' page
    return redirect(url_for('admin_dashboard'))


@app.context_processor
def inject_user_data():
    user_id = session.get('userID')
    cur = mysql.connection.cursor()

    # Fetch user data
    cur.execute("SELECT username, email FROM users WHERE id = %s", (user_id,))
    user_data = cur.fetchone()

    # Fetch goal data sorted by priority (high to low)
    cur.execute("SELECT * FROM goal WHERE user_id = %s ORDER BY FIELD(priority, 'high', 'medium', 'low')", (user_id,))
    goals = cur.fetchall()

    # Close the cursor
    cur.close()

    current_currency = session.get('current_currency', 'USD')  # Use the session variable

   # Return a dictionary with user_data and goals
    return dict(user_data=user_data, goals=goals,current_currency=current_currency)

@app.route('/category_report', methods=['GET', 'POST'])
@is_logged_in
def categoryReport():
    cur = mysql.connection.cursor()

    if request.method == 'POST':
        year = request.form.get('year')

        # Fetch income data for each category and month for the selected year or all years
        income_query = "SELECT SUM(amount) AS total, category, MONTH(date) as month FROM transactions WHERE user_id = %s AND amount > 0 "
        params = [session['userID']]
        if year:
            income_query += "AND YEAR(date) = %s "
            params.append(int(year))
        income_query += "GROUP BY category, month ORDER BY category, month"

        cur.execute(income_query, params)
        income_data = cur.fetchall()

        # Fetch outcome data for each category and month for the selected year or all years
        outcome_query = "SELECT SUM(amount) AS total, source, MONTH(date) as month FROM income WHERE user_id = %s AND amount > 0 "
        params = [session['userID']]
        if year:
            outcome_query += "AND YEAR(date) = %s "
            params.append(int(year))
        outcome_query += "GROUP BY source, month ORDER BY source, month"

        cur.execute(outcome_query, params)
        outcome_data = cur.fetchall()

        cur.close()
        if not income_data and not outcome_data:
            flash('No data available for the selected year', 'warning')

        return render_template('category_report.html', income_data=income_data, outcome_data=outcome_data, selected_year=year)

    # Handle the case when the form is not submitted (show data for all years and months)
    income_query = "SELECT SUM(amount) AS total, category, MONTH(date) as month FROM transactions WHERE user_id = %s AND amount > 0 GROUP BY category, month ORDER BY category, month"
    cur.execute(income_query, [session['userID']])
    income_data = cur.fetchall()

    outcome_query = "SELECT SUM(amount) AS total, source, MONTH(date) as month FROM income WHERE user_id = %s AND amount > 0 GROUP BY source, month ORDER BY source, month"
    cur.execute(outcome_query, [session['userID']])
    outcome_data = cur.fetchall()

    cur.close()

    return render_template('category_report.html', income_data=income_data, outcome_data=outcome_data, selected_year=None)

@app.route('/download_csv/<year>', methods=['GET'])
@is_logged_in
def download_csv(year):
    cur = mysql.connection.cursor()
    if year == 'all':
        # Fetch total income for each category for all years
        cur.execute(
            f"SELECT SUM(amount) AS total, category, YEAR(date) AS year FROM transactions "
            f"WHERE user_id = {session['userID']} AND amount > 0 GROUP BY category, year ORDER BY category, year"
        )
        income_data_all_years = cur.fetchall()

        # Fetch total outcome for each category for all years
        cur.execute(
            f"SELECT SUM(amount) AS total, source, YEAR(date) AS year FROM income "
            f"WHERE user_id = {session['userID']} AND amount > 0 GROUP BY source, year ORDER BY source, year"
        )
        outcome_data_all_years = cur.fetchall()

        # Convert amounts based on the selected currency
        currency = session.get('current_currency', 'USD')
        converted_income_data = convert_currency(income_data_all_years, currency)
        converted_outcome_data = convert_currency(outcome_data_all_years, currency)

        # Create CSV data for all years
        csv_data = []
        csv_data.append({'Category': 'Total Outcome', 'Total': sum(item['total'] for item in converted_income_data)})
        csv_data.extend({'Category': f"{item['category']} ({item['year']})", 'Total': item['total']} for item in converted_income_data)

        csv_data.append({'Category': 'Total Income', 'Total': sum(item['total'] for item in converted_outcome_data)})
        csv_data.extend({'Category': f"{item['source']} ({item['year']})", 'Total': item['total']} for item in converted_outcome_data)

        return send_csv(csv_data, f'Category_Report_All_Years.csv', ['Category', 'Total'])
    else:
        # Fetch total income for each category for the selected year
        cur.execute(
            f"SELECT SUM(amount) AS total, category FROM transactions "
            f"WHERE user_id = {session['userID']} AND amount > 0 AND YEAR(date) = {year} GROUP BY category ORDER BY category"
        )
        income_data = cur.fetchall()

        # Fetch total outcome for each category for the selected year
        cur.execute(
            f"SELECT SUM(amount) AS total, source FROM income "
            f"WHERE user_id = {session['userID']} AND amount > 0 AND YEAR(date) = {year} GROUP BY source ORDER BY source"
        )
        outcome_data = cur.fetchall()

        # Convert amounts based on the selected currency
        currency = session.get('current_currency', 'USD')
        converted_income_data = convert_currency(income_data, currency)
        converted_outcome_data = convert_currency(outcome_data, currency)

        # Create CSV data for the selected year
        csv_data = []
        csv_data.append({'Category': 'Total Outcome', 'Total': sum(item['total'] for item in converted_income_data)})
        csv_data.extend({'Category': item['category'], 'Total': item['total']} for item in converted_income_data)

        csv_data.append({'Category': 'Total Income', 'Total': sum(item['total'] for item in converted_outcome_data)})
        csv_data.extend({'Category': item['source'], 'Total': item['total']} for item in converted_outcome_data)

        return send_csv(csv_data, f'Category_Report_{year}.csv', ['Category', 'Total'])

def convert_currency(data, currency):
    conversion_rate = 4100  # Adjust the conversion factor as needed
    for item in data:
        item['total'] = item['total'] * conversion_rate if currency == 'KHR' else item['total']
    return data

def send_csv(data, filename, fields):
    si = StringIO()
    cw = csv.DictWriter(si, fieldnames=fields)
    cw.writeheader()
    cw.writerows(data)
    response = make_response(si.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return response

def month_abbreviation(month):
    return [
        'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
    ][month - 1]

# Add this function to get available years from your data
def get_available_years():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT DISTINCT YEAR(date) AS year FROM transactions WHERE user_id = {session['userID']} UNION SELECT DISTINCT YEAR(date) AS year FROM income WHERE user_id = {session['userID']} ORDER BY year DESC"
    )
    years = [year['year'] for year in cur.fetchall()]
    cur.close()
    return years

@app.route('/monthly_yearly_report', methods=['GET', 'POST'])
@is_logged_in
def monthlyYearlyReport():
    cur = mysql.connection.cursor()

    # Get available years for the filter
    available_years = get_available_years()

    if request.method == 'POST':
        selected_month = request.form.get('month', '00')
        selected_year = request.form.get('year', '0')

        # Fetch total income for each category for the selected month and year
        cur.execute(
            f"SELECT SUM(amount) AS total, category, description, YEAR(date) AS year, MONTH(date) AS month FROM transactions WHERE user_id = {session['userID']} AND amount > 0 AND MONTH(date) = {selected_month} AND YEAR(date) = {selected_year} GROUP BY category, description, year, month ORDER BY category, year, month"
        )
        income_data_filtered = cur.fetchall()

        # Fetch total outcome for each source for the selected month and year
        cur.execute(
            f"SELECT SUM(amount) AS total, source, description, YEAR(date) AS year, MONTH(date) AS month FROM income WHERE user_id = {session['userID']} AND amount > 0 AND MONTH(date) = {selected_month} AND YEAR(date) = {selected_year} GROUP BY source, description, year, month ORDER BY source, year, month"
        )
        outcome_data_filtered = cur.fetchall()

        if not income_data_filtered and not outcome_data_filtered:
            flash('No data available for the selected year', 'warning')
            return render_template('monthly_yearly_report.html', income_data_all=income_data_filtered, outcome_data_all=outcome_data_filtered, month_abbreviation=month_abbreviation, available_years=available_years)
        cur.close()

        return render_template('monthly_yearly_report.html', income_data_all=income_data_filtered, outcome_data_all=outcome_data_filtered, month_abbreviation=month_abbreviation, available_years=available_years)

    # Fetch total income for each category for all months and years
    cur.execute(
        f"SELECT SUM(amount) AS total, category, description, YEAR(date) AS year, MONTH(date) AS month FROM transactions WHERE user_id = {session['userID']} AND amount > 0 GROUP BY category, description, year, month ORDER BY category, year, month"
    )
    income_data_all = cur.fetchall()

    # Fetch total outcome for each source for all months and years
    cur.execute(
        f"SELECT SUM(amount) AS total, source, description, YEAR(date) AS year, MONTH(date) AS month FROM income WHERE user_id = {session['userID']} AND amount > 0 GROUP BY source, description, year, month ORDER BY source, year, month"
    )
    outcome_data_all = cur.fetchall()

    cur.close()

    return render_template('monthly_yearly_report.html', income_data_all=income_data_all, outcome_data_all=outcome_data_all, month_abbreviation=month_abbreviation, available_years=available_years)


def get_available_years_bill():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT DISTINCT YEAR(expiration_date) AS year FROM bills WHERE user_id = {session['userID']} ORDER BY year DESC"
    )
    years = [year['year'] for year in cur.fetchall()]
    cur.close()
    return years

def status_abbreviation(status):
    status = int(status)
    return [
        'Paid', 'Unpaid'
    ][status - 1]

@app.route('/bill_report', methods=['GET', 'POST'])
@is_logged_in
def bill_report():
    cur = mysql.connection.cursor()
    available_years = get_available_years_bill()
    if request.method == "POST":
        selected_month = request.form.get('month', '00')
        selected_year = request.form.get('year', '0')
        cur.execute(
            f"SELECT SUM(amount) AS total, category, description, paid, YEAR(expiration_date) AS year, MONTH(expiration_date) AS month FROM bills WHERE user_id = {session['userID']} AND amount > 0 AND MONTH(expiration_date) = {selected_month} AND YEAR(expiration_date) = {selected_year} GROUP BY category, description, paid, year, month ORDER BY category, year, month"
        )
        bill_data_filter = cur.fetchall()
        cur.close()

        if not bill_data_filter:
            flash('No data available for the selected year', 'warning')

        return render_template('bill_report.html', bill_data_all=bill_data_filter, month_abbreviation=month_abbreviation, status_abbreviation=status_abbreviation, available_years=available_years)

    cur.execute(
        f"SELECT SUM(amount) AS total, category, description, paid, YEAR(expiration_date) AS year, MONTH(expiration_date) AS month FROM bills WHERE user_id = {session['userID']} AND amount > 0 GROUP BY category, description, paid, year, month ORDER BY category, year, month"
    )
    bill_data_all = cur.fetchall()
    cur.close()
    return render_template('bill_report.html', bill_data_all=bill_data_all, month_abbreviation=month_abbreviation, status_abbreviation=status_abbreviation, available_years=available_years)


def get_available_years_goal():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT DISTINCT YEAR(target_date) AS year FROM goal WHERE user_id = {session['userID']} ORDER BY year DESC"
    )
    years = [year['year'] for year in cur.fetchall()]
    cur.close()
    return years

@app.route('/goal_report', methods=['GET', 'POST'])
@is_logged_in
def goal_report():
    get_available_years = get_available_years_goal()

    if request == 'POST':
        selected_month = request.form.get('month', '00')
        selected_year = request.form.get('year', '0')
        cur.execute(
            f"SELECT SUM(amount) AS total, category, description, paid, YEAR(expiration_date) AS year, MONTH(expiration_date) AS month FROM bills WHERE user_id = {session['userID']} AND amount > 0 AND MONTH(expiration_date) = {selected_month} AND YEAR(expiration_date) = {selected_year} GROUP BY category, description, paid, year, month ORDER BY category, year, month"
        )
        goal_data_filter = cur.fetchall()
        cur.close()

        if not goal_data_filter:
            flash('No data available for the selected year', 'warning')

        return render_template('goal_report.html', goal_data_all=goal_data_filter, month_abbreviation=month_abbreviation, available_years=get_available_years_goal())
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT SUM(amount) AS total, category, description, priority, status, YEAR(target_date) AS year, MONTH(target_date) AS month FROM goal WHERE user_id = {session['userID']} AND amount > 0 GROUP BY category, description, priority, year, month, status ORDER BY category, year, month, status"
    )
    goal_data_all = cur.fetchall()
    cur.close()
    return render_template('goal_report.html', goal_data_all=goal_data_all, month_abbreviation=month_abbreviation, available_years=get_available_years_goal())

def convert_amount_to_currency(amount, currency):
    if currency == 'USD':
        return amount
    elif currency == 'KHR':
        return amount * 4100

@app.route('/download_goal_csv', methods=['GET', 'POST'])
@is_logged_in
def download_goal_csv():
    cur = mysql.connection.cursor()
    currency = session.get('current_currency', 'USD')
    if request.method == 'POST':
        year = request.form.get('year')
        month = request.form.get('month')
        cur.execute(
            f"SELECT SUM(amount) AS total, category, description, priority, status, YEAR(target_date) AS year, MONTH(target_date) AS month FROM goal WHERE user_id = {session['userID']} AND amount > 0 AND YEAR(target_date) = {year} AND MONTH(target_date) = {month} GROUP BY category, description, priority, year, month, status ORDER BY category, year, month, status"
        )
        goal_data = cur.fetchall()
        csv_data = StringIO()
        csv_writer = csv.writer(csv_data)
        csv_writer.writerow(['Category', 'Total', 'Description', 'Priority', 'Status', 'Year', 'Month'])

        # Write goal data to CSV
        for item in goal_data:
            csv_writer.writerow([item['category'], convert_amount_to_currency(item['total'], currency), item['description'], item['priority'], item['status'], item['year'], item['month']])

        # Create a Flask Response with the CSV file
        response = Response(csv_data.getvalue(), mimetype='text/csv')
        response.headers['Content-Disposition'] = f'attachment; filename=goal_report_{year}_{month}.csv'

        return response
    else:
        cur.execute(
            f"SELECT SUM(amount) AS total, category, description, priority, status, YEAR(target_date) AS year, MONTH(target_date) AS month FROM goal WHERE user_id = {session['userID']} AND amount > 0 GROUP BY category, description, priority, year, month, status ORDER BY category, year, month, status"
        )
        goal_data = cur.fetchall()
        csv_data = StringIO()
        csv_writer = csv.writer(csv_data)
        csv_writer.writerow(['Category', 'Total', 'Description', 'Priority', 'Status', 'Year', 'Month'])

        # Write goal data to CSV
        for item in goal_data:
            csv_writer.writerow([item['category'], convert_amount_to_currency(item['total'], currency), item['description'], item['priority'], item['status'], item['year'], item['month']])

        # Create a Flask Response with the CSV file
        response = Response(csv_data.getvalue(), mimetype='text/csv')
        response.headers['Content-Disposition'] = 'attachment; filename=goal_report.csv'

        return response

@app.route('/download_bill_csv', methods=['GET', 'POST'])
@is_logged_in
def download_bill_csv():
    currency = session.get('current_currency', 'USD')
    cur = mysql.connection.cursor()
    if request.method == 'POST':
        year = request.form.get('year')
        month = request.form.get('month')
        cur.execute(
            f"SELECT SUM(amount) AS total, category, description, paid, DAY(expiration_date) AS day, YEAR(expiration_date) AS year, MONTH(expiration_date) AS month, DATE_FORMAT(expiration_date, '%%d-%%m-%%Y') AS date FROM bills WHERE user_id = {session['userID']} AND amount > 0 AND YEAR(expiration_date) = {year} AND MONTH(expiration_date) = {month} GROUP BY category, description, paid, year, day, month, date ORDER BY category, year, month, day, date"
        )
        bill_data = cur.fetchall()
        csv_data = StringIO()
        csv_writer = csv.writer(csv_data)
        csv_writer.writerow(['Category', 'Total', 'Description', 'Paid', 'Year', 'Month', 'Day'])

        # Write bill data to CSV
        for item in bill_data:
            csv_writer.writerow([item['category'], convert_amount_to_currency(item['total'], currency), item['description'], status_abbreviation(item['paid']), item['year'], item['month'], item['day']])

        # Create a Flask Response with the CSV file
        response = Response(csv_data.getvalue(), mimetype='text/csv')
        response.headers['Content-Disposition'] = f'attachment; filename=bill_report_{year}_{month}.csv'

        return response
    else:
        cur.execute(
            f"SELECT SUM(amount) AS total, category, description, paid, DAY(expiration_date) AS day, YEAR(expiration_date) AS year, MONTH(expiration_date) AS month FROM bills WHERE user_id = {session['userID']} AND amount > 0 GROUP BY category, description, paid, year, month, day, expiration_date ORDER BY category, year, month, day"
        )
        bill_data = cur.fetchall()
        csv_data = StringIO()
        csv_writer = csv.writer(csv_data)
        csv_writer.writerow(['Category', 'Total', 'Description', 'Paid', 'Year', 'Month', 'Day'])

        # Write bill data to CSV
        for item in bill_data:
            csv_writer.writerow([item['category'], convert_amount_to_currency(item['total'], currency), item['description'], status_abbreviation(item['paid']), item['year'], item['month'], item['day']])

        # Create a Flask Response with the CSV file
        response = Response(csv_data.getvalue(), mimetype='text/csv')
        response.headers['Content-Disposition'] = 'attachment; filename=bill_report.csv'

        return response

@app.route('/download_income_csv', methods=['GET', 'POST'])
@is_logged_in
def download_income_csv():
    currency = session.get('current_currency', 'USD')
    cur = mysql.connection.cursor()
    if request.method == 'POST':
        year = request.form.get('year')
        month = request.form.get('month')
        cur.execute(
            f"SELECT SUM(amount) AS total, source, description, DAY(date) AS day, YEAR(date) AS year, MONTH(date) AS month, DATE_FORMAT(date, '%%d-%%m-%%Y') AS date FROM income WHERE user_id = {session['userID']} AND amount > 0 AND YEAR(date) = {year} AND MONTH(date) = {month} GROUP BY source, description, date ORDER BY source, date"
        )
        income_data = cur.fetchall()
        csv_data = StringIO()   
        csv_writer = csv.writer(csv_data)
        csv_writer.writerow(['source', 'Total', 'Description', 'Year', 'Month', 'Day'])  # Include the 'Date' column

        # Write income data to CSV
        for item in income_data:
            csv_writer.writerow([item['source'], convert_amount_to_currency(item['total'], currency), item['description'], item['year'], item['month'], item['day']])

        # Create a Flask Response with the CSV file
        response = Response(csv_data.getvalue(), mimetype='text/csv')
        response.headers['Content-Disposition'] = f'attachment; filename=income_report_{year}_{month}.csv'

        return response
    else:
        cur.execute(
            f"SELECT SUM(amount) AS total, source, description, DAY(date) AS day, YEAR(date) AS year, MONTH(date) AS month FROM income WHERE user_id = {session['userID']} AND amount > 0 GROUP BY source, description, year, month, day ORDER BY source, year, month"
        )
        income_data = cur.fetchall()

        # Create a CSV file in memory
        csv_data = StringIO()
        csv_writer = csv.writer(csv_data)
        csv_writer.writerow(['Source', 'Total', 'Description', 'Year', 'Month', 'Day'])  # Adjust headers as needed

        # Write income data to CSV
        for item in income_data:
            csv_writer.writerow([item['source'], convert_amount_to_currency(item['total'], currency), item['description'], item['year'], item['month'], item['day']])

        # Create a Flask Response with the CSV file
        response = Response(csv_data.getvalue(), mimetype='text/csv')
        response.headers['Content-Disposition'] = 'attachment; filename=income_report.csv'

        return response


@app.route('/download_outcome_csv', methods=['GET', 'POST'])
@is_logged_in
def download_outcome_csv():
    currency = session.get('current_currency', 'USD')
    cur = mysql.connection.cursor()
    if request.method == 'POST':
        year = request.form.get('year')
        month = request.form.get('month')
        cur.execute(
            f"SELECT SUM(amount) AS total, category, description, DAY(date) AS day, YEAR(date) AS year, MONTH(date) AS month, DATE_FORMAT(date, '%%d-%%m-%%Y') AS date FROM transactions WHERE user_id = {session['userID']} AND amount > 0 AND YEAR(date) = {year} AND MONTH(date) = {month} GROUP BY category, description, date ORDER BY category, date"
        )
        outcome_data = cur.fetchall()
        csv_data = StringIO()
        csv_writer = csv.writer(csv_data)
        csv_writer.writerow(['Category', 'Total', 'Description', 'Year', 'Month']) 

        # Write outcome data to CSV
        for item in outcome_data:
            csv_writer.writerow([item['category'], convert_amount_to_currency(item['total'], currency), item['description'], item['year'], item['month'], item['day']])

        # Create a Flask Response with the CSV file
        response = Response(csv_data.getvalue(), mimetype='text/csv')
        response.headers['Content-Disposition'] = f'attachment; filename=outcome_report_{year}_{month}.csv'

        return response
    else: 
        # Fetch outcome data from your database (replace with your data fetching logic)
        cur = mysql.connection.cursor()
        cur.execute(
            f"SELECT SUM(amount) AS total, category, description, DAY(date) AS day, YEAR(date) AS year, MONTH(date) AS month FROM transactions WHERE user_id = {session['userID']} AND amount > 0 GROUP BY category, description, year, month, day ORDER BY category, year, month"
        )
        outcome_data = cur.fetchall()
        cur.close()

        # Create a CSV file in memory
        csv_data = StringIO()
        csv_writer = csv.writer(csv_data)
        csv_writer.writerow(['Category', 'Total', 'Description', 'Year', 'Month', 'Day'])  # Adjust headers as needed

        # Write outcome data to CSV
        for item in outcome_data:
            csv_writer.writerow([item['category'], convert_amount_to_currency(item['total'], currency), item['description'], item['year'], item['month'], item['day']])

        # Create a Flask Response with the CSV file
        response = Response(csv_data.getvalue(), mimetype='text/csv')
        response.headers['Content-Disposition'] = 'attachment; filename=outcome_report.csv'

        return response
    
@app.route('/expense_trend')
def expense_trend():
    user_id = session.get('userID')

    # Fetch income data from MySQL for the current year
    today = date.today()
    start_of_year = date(today.year, 1, 1)
    cur = mysql.connection.cursor()

        # Fetch expense data for the current month
    cur.execute("""
        SELECT 
            IFNULL(SUM(amount), 0) AS total_expense
        FROM transactions 
        WHERE user_id = %s 
            AND DATE(date) BETWEEN %s AND %s
    """, (user_id, date(today.year, today.month, 1), today))

    current_month_expense = cur.fetchone()["total_expense"]

    # Fetch expense data for the previous month
    first_day_of_previous_month = date(today.year, today.month - 1, 1) if today.month > 1 else date(today.year - 1, 12, 1)
    last_day_of_previous_month = date(today.year, today.month, 1) - timedelta(days=1)

    cur.execute("""
        SELECT 
            IFNULL(SUM(amount), 0) AS total_expense
        FROM transactions 
        WHERE user_id = %s 
            AND DATE(date) BETWEEN %s AND %s
    """, (user_id, first_day_of_previous_month, last_day_of_previous_month))

    previous_month_expense = cur.fetchone()["total_expense"]

    # Calculate the percentage change
    percentage_change = 0
    if previous_month_expense != 0:
        percentage_change = ((current_month_expense - previous_month_expense) / previous_month_expense) * 100
        # Secure the percentage change within the range [-100%, 100%]
        percentage_change = max(min(percentage_change, 100), -100)
    else:
        # Handle the case where previous_month_expense is 0 to avoid division by zero
        percentage_change = 0
    percentage_change = round(percentage_change, 2)

    if percentage_change > 0:
        percentage_change_message = f"Attention! Your expenses have increased by {abs(percentage_change):.2f}% compared to the previous month. Consider reviewing your spending habits and finding opportunities to optimize your expenses."
    elif percentage_change < 0:
        percentage_change_message = f"Good job! You've managed to reduce your expenses by {abs(percentage_change):.2f}% compared to the previous month. Keep up the good work in managing your finances efficiently."
    else:
        percentage_change_message = "Your expenses have remained the same compared to the previous month. Continue monitoring your spending and make informed financial decisions."    
    
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT 
            COALESCE(MONTH(STR_TO_DATE(date, '%%Y-%%m-%%d %%H:%%i:%%s')), 0) AS month, 
            IFNULL(SUM(amount), 0) AS total_income
        FROM income 
        WHERE user_id = %s 
            AND DATE(date) BETWEEN %s AND %s
        GROUP BY month
        ORDER BY month
    """, (user_id, start_of_year, today))

    income_data = cur.fetchall()

    # Fetch expense data from MySQL for the current year
    cur.execute("""
        SELECT 
            COALESCE(MONTH(STR_TO_DATE(date, '%%Y-%%m-%%d %%H:%%i:%%s')), 0) AS month, 
            IFNULL(SUM(amount), 0) AS total_expense
        FROM transactions 
        WHERE user_id = %s 
            AND DATE(date) BETWEEN %s AND %s
        GROUP BY month
        ORDER BY month
    """, (user_id, start_of_year, today))

    expense_data = cur.fetchall()

    # Fetch sum of all transactions from the last 30 days
    thirty_days_ago = today - timedelta(days=30)
    cur.execute("""
        SELECT IFNULL(SUM(amount), 0) AS total_last_30_days
        FROM transactions 
        WHERE user_id = %s 
            AND DATE(date) BETWEEN %s AND %s
    """, (user_id, thirty_days_ago, today))

    transactions_last_30_days = cur.fetchone()["total_last_30_days"]

    # Calculate balance and score
    balance_data = []
    total_score = 0

    for i in range(1, 13):
        income = next((item["total_income"] for item in income_data if item["month"] == i), 0)
        expense = next((item["total_expense"] for item in expense_data if item["month"] == i), 0)

        if income == 0 or expense == 0:
            continue  # Skip months with both income and expense as 0

        balance = income - expense
        score = balance / income if balance != 0 else 0
        total_score += score

        balance_data.append({"Month": i, "Balance": balance, "Score": score})

    balance_data_chart = []

    for i in range(1, 13):
        income = next((item["total_income"] for item in income_data if item["month"] == i), 0)
        expense = next((item["total_expense"] for item in expense_data if item["month"] == i), 0)

        if income == 0 or expense == 0:
            balance = 0
            score = 0
        else:
            balance = income - expense
            score = balance / income if balance != 0 else 0

        balance_data_chart.append({"Month": i, "Balance": balance, "Score": score})

    # Determine suggestions based on total score
    average_score = total_score / len(balance_data)
    suggestions = ""
    user_score = 0

    if average_score == 0:
        user_score = 0
    elif average_score < 0.85 and average_score > 0:
        if average_score < 0.65:
            user_score = 100
        else:
            user_score = int((0.85 - float(average_score)) / 0.19 * 48) + 51
            user_score = min(user_score, 99)

    elif average_score == 0.8:
        user_score = 50
    else:
        user_score = int((1.0 - float(average_score)) / 0.14 * 39) + 10
        # Ensure the user score is capped at 49
        user_score = min(user_score, 49)

    if user_score == 0:
        suggestions = "You have not made any income or expense this year."
    elif user_score == 100:
        suggestions = "Fantastic! You've achieved a perfect financial balance. Your money management skills are exceptional!"
    elif user_score >= 80:
        suggestions = "Great job! Your financial health is robust, and you're making smart choices with your money."
    elif user_score >= 65:
        suggestions = "Not bad! Your financial well-being is decent, but there's room for improvement. Keep an eye on your spending habits."
    elif user_score >= 45:
        suggestions = "You're doing okay! Your financial health is average. Consider exploring opportunities to optimize your expenses."
    elif user_score >= 35:
        suggestions = "Caution! Your financial health needs attention. It's time to review your spending and find ways to cut down on unnecessary expenses."
    elif user_score >= 10:
        suggestions = "Warning! Your financial health is at risk. Take immediate steps to reduce expenses and improve your financial situation."
    else:
        suggestions = "Emergency! Your financial health is critical. Urgent action is required to control expenses and enhance your financial well-being."

    return render_template('expense_trend.html',transactions_last_30_days=transactions_last_30_days, balance_data_chart=balance_data_chart, user_score=user_score, suggestions=suggestions, percentage_change=percentage_change, active_page='trend')


def get_total_income(selected_month, selected_year):
    try:
        # Create a cursor
        cur = mysql.connection.cursor()

        # Execute the query
        cur.execute(
            "SELECT SUM(amount) as total_income FROM income WHERE MONTH(date) = %s AND YEAR(date) = %s AND user_id = %s",
            (selected_month, selected_year, session['userID'])
        )

        # Fetch the result
        income_data = cur.fetchone()

        # Return the total income or 0 if no income data
        return income_data['total_income'] or 0

    except Exception as e:
        # Handle exceptions appropriately (e.g., log the error)
        print(f"Error in get_total_income: {e}")
        return 0

    finally:
        # Close the cursor
        cur.close()

def get_total_expenses(selected_month, selected_year):
    try:
        # Create a cursor
        cur = mysql.connection.cursor()

        # Execute the query
        cur.execute(
            "SELECT SUM(amount) as total_expenses FROM transactions WHERE MONTH(date) = %s AND YEAR(date) = %s AND user_id = %s",
            (selected_month, selected_year, session['userID'])
        )

        # Fetch the result
        expenses_data = cur.fetchone()

        # Return the total expenses or 0 if no expenses data
        return expenses_data['total_expenses'] or 0

    except Exception as e:
        # Handle exceptions appropriately (e.g., log the error)
        print(f"Error in get_total_expenses: {e}")
        return 0

    finally:
        # Close the cursor
        cur.close()

def get_profit(selected_month, selected_year):
    total_income = get_total_income(selected_month, selected_year)
    total_expenses = get_total_expenses(selected_month, selected_year)
    return total_income - total_expenses

def get_last_month_profit(selected_month, selected_year):
    try:
        # Create a cursor
        cur = mysql.connection.cursor()

        # Execute the query for the last month of the selected year
        cur.execute(
            "SELECT SUM(amount) as profit_last_month FROM income WHERE MONTH(date) = %s AND YEAR(date) = %s AND user_id = %s",
            (selected_month, selected_year, session['userID'])
        )

        # Fetch the result
        last_month_profit_data = cur.fetchone()

        # Return the last month's profit or 0 if no data
        return last_month_profit_data['profit_last_month'] or 0

    except Exception as e:
        # Handle exceptions appropriately (e.g., log the error)
        print(f"Error in get_last_month_profit: {e}")
        return 0

    finally:
        # Close the cursor
        cur.close()


def get_last_year_profit(selected_month, selected_year):
    try:
        # Create a cursor
        cur = mysql.connection.cursor()

        # Calculate the previous year
        previous_year = selected_year - 1

        # Execute the query for the total income of the previous year
        cur.execute(
            "SELECT SUM(amount) as total_income_last_year FROM income WHERE YEAR(date) = %s AND user_id = %s",
            (previous_year, session['userID'])
        )

        # Fetch the result
        total_income_last_year_data = cur.fetchone()
        total_income_last_year = total_income_last_year_data['total_income_last_year'] or 0

        # Execute the query for the total expenses of the previous year
        cur.execute(
            "SELECT SUM(amount) as total_expenses_last_year FROM transactions WHERE YEAR(date) = %s AND user_id = %s",
            (previous_year, session['userID'])
        )

        # Fetch the result
        total_expenses_last_year_data = cur.fetchone()
        total_expenses_last_year = total_expenses_last_year_data['total_expenses_last_year'] or 0

        # Calculate the last year's profit
        last_year_profit = total_income_last_year - total_expenses_last_year

        # Return the last year's profit
        return last_year_profit

    except Exception as e:
        # Handle exceptions appropriately (e.g., log the error)
        print(f"Error in get_last_year_profit: {e}")
        return 0

    finally:
        # Close the cursor
        cur.close()


@app.route('/budget_projection', methods=['GET', 'POST'])
@is_logged_in
def budget_projection():
    try:
        # Create a cursor
        cur = mysql.connection.cursor()

        # Default values for the current month and year
        selected_year = dt.now().year
        selected_month = dt.now().month

        # If the form is submitted, use the selected month and year
        if request.method == 'POST':
            selected_month = int(request.form.get('selected_month'))
            selected_year = int(request.form.get('selected_year'))

        # Get distinct years from both income and transactions tables
        cur.execute(
            "SELECT DISTINCT YEAR(date) AS transaction_year FROM transactions WHERE user_id = %s "
            "UNION "
            "SELECT DISTINCT YEAR(date) AS income_year FROM income WHERE user_id = %s",
            (session['userID'], session['userID'])
        )
        years_data = cur.fetchall()

        # Extract unique years and sort them
        unique_years = sorted(set(year['transaction_year'] for year in years_data if year['transaction_year'] is not None))

        # Get monthly income and expenses for the selected year
        cur.execute(
            "SELECT MONTH(date) AS month, SUM(amount) as total_income "
            "FROM income WHERE YEAR(date) = %s AND user_id = %s "
            "GROUP BY MONTH(date) ORDER BY MONTH(date)",
            (selected_year, session['userID'])
        )
        income_data = cur.fetchall()

        cur.execute(
            "SELECT MONTH(date) AS month, SUM(amount) as total_expenses "
            "FROM transactions WHERE YEAR(date) = %s AND user_id = %s "
            "GROUP BY MONTH(date) ORDER BY MONTH(date)",
            (selected_year, session['userID'])
        )
        expenses_data = cur.fetchall()

        # Map month numbers to month names
        month_names = {
            1: "Jan", 2: "Feb", 3: "Mar", 4: "Apr", 5: "May", 6: "Jun",
            7: "Jul", 8: "Aug", 9: "Sep", 10: "Oct", 11: "Nov", 12: "Dec"
        }

        # Convert month numbers to month names in income_data and expenses_data
        income_data = [{'month': month_names[month['month']], 'total_income': month['total_income']} for month in income_data]
        expenses_data = [{'month': month_names[month['month']], 'total_expenses': month['total_expenses']} for month in expenses_data]

        # Close the cursor
        cur.close()

        # Calculate cumulative income and cumulative expenses
        cumulative_income = [
            {'month': month['month'], 'total': cumulative_income}
            for cumulative_income, month in zip(itertools.accumulate([month['total_income'] for month in income_data]), income_data)
        ]

        cumulative_expenses = [
            {'month': month['month'], 'total': cumulative_expenses}
            for cumulative_expenses, month in zip(itertools.accumulate([month['total_expenses'] for month in expenses_data]), expenses_data)
        ]


        # Calculate total profit and total profit of last year
        total_profit = get_profit(selected_month, selected_year)
        total_profit_last_year = get_last_year_profit(selected_month, selected_year)

        
        # Render the template with the updated values
        return render_template('budget_projection.html',
                                total_income=get_total_income(selected_month, selected_year),
                                total_expenses=get_total_expenses(selected_month, selected_year),
                                profit=total_profit,
                                profit_last_year=total_profit_last_year,
                                total_profit_for_chart=total_profit,
                                total_profit_last_year_for_chart=total_profit_last_year,
                                current_year=dt.now().year,
                                unique_years=unique_years,
                                income_data=income_data,
                                expenses_data=expenses_data,
                                selected_year=selected_year,
                                selected_month=selected_month,
                                cumulative_income=cumulative_income,
                                cumulative_expenses=cumulative_expenses,
                                active_page='budget')

    except Exception as e:
        raise e