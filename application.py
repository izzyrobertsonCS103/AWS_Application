from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask import Flask, render_template, request, url_for, redirect, logging, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import pymysql
from flask_migrate import Migrate
import os

pymysql.install_as_MySQLdb()

application = Flask(__name__)  # created flask instance
login_manager = LoginManager(application)
#if 'RDS_DB_NAME' in os.environ:
application.config['SQLALCHEMY_DATABASE_URI'] = ''#Hidden URI for security purposes

application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

application.config['SECRET_KEY'] = "secret_key"

db = SQLAlchemy(application)  # initialise the database

migrate = Migrate(application, db)


class Users(db.Model, UserMixin):  # creating model
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), nullable=False)
    f_name = db.Column(db.String(200), nullable=False)
    l_name = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    income = db.relationship('Income', backref='users')
    expense = db.relationship('Expense', backref='users')
    goal = db.relationship('Goal', backref='users')
    budget = db.relationship('Budget', backref='users')

    def __repr__(self):  # creating a string
        return '<name %r>' % self.id


class Income(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    income_amount = db.Column(db.Integer, nullable=False)
    income_source = db.Column(db.Text)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    users_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    expense_amount = db.Column(db.Integer, nullable=False)
    expense_source = db.Column(db.Text)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    users_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class Goal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    goal_amount = db.Column(db.Integer, nullable=False)
    goal_info = db.Column(db.String(200))
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    users_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    budget_amount = db.Column(db.Integer, nullable=False)
    budget_length = db.Column(db.Text)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    users_id = db.Column(db.Integer, db.ForeignKey('users.id'))


@login_manager.user_loader
def load_user(users_id):
    return Users.query.get(int(users_id))  # uses the user id to load users


@application.route('/')
def main():
    if current_user.is_authenticated:  # checks if user is logged in (did not log out since last time)
        return redirect(url_for('home'))
    return redirect(url_for('login'))  # delete cache or log out before closing window to go straight to login


@application.route('/home', methods=["POST", "GET"])
@login_required  # a login is required to access this route
def home():
    return render_template('home.html')


@application.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("login_email")
        password = request.form.get("login_password")

        users = Users.query.filter_by(email=email).first()
        # hash the user-supplied password and compare it to the hashed password in the database
        if not users or not check_password_hash(users.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))  # if the user doesn't exist or password is wrong, reload the page

        login_user(users, remember=True)  # logs in user and remembers who they are so that they can pass login_required
        return redirect(url_for('home'))
    return render_template('login.html')


@application.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user_email = request.form.get("email")
        user_first_name = request.form.get("first_name")
        user_last_name = request.form.get("last_name")
        user_password = request.form.get("password")
        hash_pw = generate_password_hash(user_password, method='sha256')  # hash the password for protection
        new_user = Users(email=user_email, f_name=user_first_name, l_name=user_last_name, password=hash_pw)  # creating new user
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')

    else:
        users = Users.query.order_by(Users.date_added)
        return render_template('login.html', users=users)


@application.route('/income', methods=["GET", "POST"])
@login_required
def income():
    if request.method == "POST":
        income_amount = request.form.get("income_amount")
        income_source = request.form.get("income_source")
        user_id = current_user.id
        new_income = Income(income_amount=income_amount, income_source=income_source, users_id=user_id)
        db.session.add(new_income)
        db.session.commit()
        flash('Income added')
        return redirect('/income')
    else:
        incomes = Income.query.order_by(Income.date_added).filter(Income.users_id == current_user.id).all()
        return render_template('income.html', income=incomes)


@application.route("/delete_income/<int:id>")
def delete_income(id):
    income_to_delete = Income.query.get_or_404(id)  # the id of Contact is used to identify which to delete
    db.session.delete(income_to_delete)  # information of user id to delete sent
    db.session.commit()
    return redirect('/income')


@application.route("/delete_expense/<int:id>")
def delete_expense(id):
    expense_to_delete = Expense.query.get_or_404(id)  # the id of Contact is used to identify which to delete
    db.session.delete(expense_to_delete)  # information of user id to delete sent
    db.session.commit()
    return redirect('/expenses')


@application.route("/delete_goal/<int:id>")
def delete_goal(id):
    goal_to_delete = Goal.query.get_or_404(id)  # the id of Contact is used to identify which to delete
    db.session.delete(goal_to_delete)  # information of user id to delete sent
    db.session.commit()
    return redirect('/goals')


@application.route("/delete_budget/<int:id>")
def delete_budget(id):
    budget_to_delete = Budget.query.get_or_404(id)  # the id of Contact is used to identify which to delete
    db.session.delete(budget_to_delete)  # information of user id to delete sent
    db.session.commit()
    return redirect('/budget')


@application.route("/update_income/<int:id>", methods=["POST", "GET"])
def update_income(id):
    income_to_update = Income.query.get_or_404(id)  # the id of Contact is used to identify which to update
    if request.method == 'POST':
        income_to_update.income_amount = request.form['income_amount']
        income_to_update.income_source = request.form['income_source']
        db.session.commit()
        return redirect('/income')
    else:
        incomes = Income.query.order_by(Income.date_added).filter(Income.users_id == current_user.id).all()
        return render_template('update_income.html', income=incomes, income_to_update=income_to_update)


@application.route("/update_expense/<int:id>", methods=["POST", "GET"])
def update_expense(id):
    expense_to_update = Expense.query.get_or_404(id)  # the id of Contact is used to identify which to update
    if request.method == 'POST':
        expense_to_update.expense_amount = request.form['expense_amount']
        expense_to_update.expense_source = request.form['expense_source']
        db.session.commit()
        return redirect('/expenses')
    else:
        expenses = Expense.query.order_by(Expense.date_added).filter(Expense.users_id == current_user.id).all()
        return render_template('update_expenses.html', expense=expenses, expense_to_update=expense_to_update)


@application.route('/expenses', methods=["GET", "POST"])
@login_required
def expenses():
    if request.method == "POST":
        expense_amount = request.form.get("expense_amount")
        expense_source = request.form.get("expense_source")
        user_id = current_user.id
        new_expense = Expense(expense_amount=expense_amount, expense_source=expense_source, users_id=user_id)
        db.session.add(new_expense)
        db.session.commit()
        flash('Expense added')
        return redirect('/expenses')
    else:
        expenses = Expense.query.order_by(Expense.date_added).filter(Expense.users_id == current_user.id).all()
        return render_template('expenses.html', expense=expenses)


@application.route('/goals', methods=["GET", "POST"])
@login_required
def goals():
    if request.method == "POST":
        goal_amount = request.form.get("goal_amount")
        goal_info = request.form.get("goal_info")
        user_id = current_user.id
        new_goal = Goal(goal_amount=goal_amount, goal_info=goal_info, users_id=user_id)
        db.session.add(new_goal)
        db.session.commit()
        flash('Goal added')
        return redirect('/goals')
    else:
        goals = Goal.query.order_by(Goal.date_added).filter(Goal.users_id == current_user.id).all()
        return render_template('goals.html', goal=goals)


@application.route('/budget', methods=["GET", "POST"])
@login_required
def budget():
    if request.method == "POST":
        budget_amount = request.form.get("budget_amount")
        budget_length = request.form.get("budget_length")
        user_id = current_user.id
        new_budget = Budget(budget_amount=budget_amount, budget_length=budget_length, users_id=user_id)
        db.session.add(new_budget)
        db.session.commit()
        flash('Budget added')
        return redirect('/budget')
    else:
        budgets = Budget.query.order_by(Budget.date_added).filter(Budget.users_id == current_user.id).all()
        return render_template('budget.html', budget=budgets)


@application.route('/logout')
def logout():
    logout_user()  # logs out the current user and sends them to login
    return redirect(url_for('login'))


if __name__ == "__main__":
    application.run(debug=False)
