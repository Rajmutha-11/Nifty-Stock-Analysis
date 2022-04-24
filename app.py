import plotly.utils
from flask import Flask,render_template,redirect,flash,url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from wtforms import StringField,SubmitField,PasswordField
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, current_user,logout_user, login_required

from fbprophet import Prophet
import pandas as pd

from nsepy import get_history
from datetime import date

import yfinance as yf
import plotly.express as px
import plotly.graph_objects as go
import json

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///stockpred.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY']='f4e3661b9412ffeed8bea85cb716ad3c'
db= SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view='login'
login_manager.login_message_category='info'



@login_manager.user_loader
def load_user(id):
# Here we tell flask-login to identify our user with the help of ID from our registration model
    return Registration.query.get(int(id))

#Models
class Registration(db.Model,UserMixin):
    #UserMixin provides a common interface that any user model needs to implement to work with Flask-Login.
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20),unique=True, nullable=False)
    name = db.Column(db.String(30),nullable=False)
    email= db.Column(db.String(30),nullable=False,unique=True)
    password= db.Column(db.String(25),nullable=False)
    time= db.Column(db.DateTime, nullable=False, default=datetime.now)

    def __repr__(self)-> str:
        return f'{self.username}-{self.name}-{self.email}'


class Login(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20),nullable=False)
    password= db.Column(db.String(25),nullable=False)
    time = db.Column(db.DateTime, nullable=False, default=datetime.now)

    def __repr__(self)-> str:
        return f'{self.username}'



#Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=5, max=20)])
    name= StringField('Username',
                           validators=[DataRequired(), Length(min=5, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password',message="Passwords must match!")])
    submit = SubmitField('Sign up')

    def validate_username(self,username):
        user= Registration.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('This username already exits.')


    def validate_email(self,email):
        user= Registration.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('This email is already registered.')



class LoginForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')




@app.route('/')
def home():
    #pandas dataframe
    nifty = get_history(symbol="NIFTY",
                        start=date(2000, 1, 1), end=date.today(),
                        index=True)
    nifty.reset_index('Date', inplace=True)
    nifty.drop(['Turnover'], axis=1, inplace=True)
    nifty_tail = nifty.tail(10)

    label = ['RIL', 'HDFC BANK', 'INFOSYS', 'ICICI BANK', 'HDFC', 'TCS', 'KOTAK MAHINDRA BANK',
              'L&T', 'HUL', 'ITC', 'BAJAJ FINANCE', 'SBI', 'BHARTI AIRTEL', 'AXIS BANK', 'ASIAN PAINTS',
              'HCL TECH','BAJAJ FINSERV', 'TITAN', 'TECH MAHINDRA', 'MARUTI SUZUKI INDIA', 'WIPRO', 'UTRATECH CEMENT',
              'TATA STEEL','TATA MOTORS', 'SUN PHARMA', 'M&M', 'POWER GRID', 'NESTLE INDIA', 'GRASIM INDUSTRIES',
              'HDFC LIFE INSURANCE', "DIVI'S LAB",'HINDALCO INDUSTRIES', 'JSW STEEL', 'NTPC', "DR REDDY'S LABS", 'INDUSLND BANK', 'ONGC',
              'SBI LIFE INSURANCE','ADANI PORTS', 'CIPLA', 'TATA CONSUMER PRODUCTS', 'BAJAJ AUTO', 'BRITANNIA INDUSTRIES', 'UPL', 'BPCL',
              'SHREE CEMENTS','EICHER MOTORS', 'COAL INDIA', 'HERO MOTOCORP', 'IOC']

    value = [10.56, 8.87, 8.62, 6.72, 6.55, 4.96, 3.91, 2.89, 2.81, 2.63, 2.52, 2.40, 2.33,
              2.29, 1.92, 1.68, 1.41,1.35, 1.30, 1.28, 1.28, 1.17, 1.14,1.12, 1.1, 1.09, 0.96,
              0.93, 0.86, 0.86, 0.84, 0.82, 0.82, 0.82, 0.77, 0.72, 0.7, 0.69, 0.68, 0.67, 0.63,
              0.57, 0.57, 0.51, 0.48, 0.47, 0.45,0.43, 0.43, 0.41]

    data = {
        'labels': label,
        'values': value,
    }

    df = pd.DataFrame(data)

    fig = px.pie(df, values='values', names='labels', labels={'labels': 'Stock', 'values': 'WEIGHTAGE'})
    fig.update_traces(textposition='inside')
    fig.update_layout(paper_bgcolor='#FFFFFF',uniformtext_minsize=12, uniformtext_mode='hide',
                      title_text='OVERVIEW OF STOCKS IN NIFTY50',title_x=0.27)


    graphJSON =json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

    return render_template('home.html',graphJSON=graphJSON,tables=[nifty_tail.to_html(classes='nifty',index=False)],
                           titles=['Nifty50 of last 10 trading sessions'])



@app.route('/search')
@login_required
def search():
    return render_template('search.html')

@app.route('/stock_analysis')
def stock_analysis():
    return render_template('stock_analysis.html')

@app.route('/signup',methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form=RegistrationForm()

    if form.validate_on_submit(): #on form submission
        #Here we hash the password entered by the user
        hashed_password= bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        #Here we collect the details, the user has filled in the form
        registered_user =  Registration(username=form.username.data, email=form.email.data,
                                        name= form.name.data ,password=hashed_password)
        #Here we add those details into the database
        db.session.add(registered_user)
        db.session.commit()
        #Here we display the flash message and redirect user to the login page
        flash("You have registered succesfully !" ,'success')
        return redirect(url_for('login'))
    return render_template('signup.html',title='Register',form=form)



@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form=LoginForm()
    if form.validate_on_submit(): #on form submission
    #Firstly we will the check if the username entered in the login form is registered from the registration model

        user= Registration.query.filter_by(username=form.username.data).first()

    #If it exists and the password entered by user is same as the hashed password used while registration
    # Then the user is logged in and is redirected to home page

        if user and bcrypt.check_password_hash(user.password,form.password.data):
            logged_in_user=Login(username=form.username.data, password = user.password)
            db.session.add(logged_in_user)
            db.session.commit()

            login_user(user)
            return redirect(url_for('home'))
        else:
            flash("Please check your email and password.",'danger')
    return render_template('login.html',title='Login',form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route("/search/adani_ports")
@login_required
def adani_ports():
    adani_ports = get_history(symbol="ADANIPORTS",
                              start=date(2000, 1, 1),
                              end=date.today())
    adani_ports_tail = adani_ports.tail(15)
    adani_ports_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1, inplace=True)
    adani_ports_tail.reset_index(inplace=True)

    adani_ports.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    adani_ports.reset_index(inplace=True)
    data = adani_ports[["Date","Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future= fbp.make_future_dataframe(periods=365)
    forecast=fbp.predict(future)

    from fbprophet.plot import plot_plotly
    fig=plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("adani_ports.html",graphJSON=graphJSON,
                           tables=[adani_ports_tail.to_html(classes='adaniports',index=False)] )


@app.route("/search/apollo_hospitals")
@login_required
def apollo_hospitals():
    apollo_hospitals = get_history(symbol="APOLLOHOSP",
                              start=date(2000, 1, 1),
                              end=date.today())
    apollo_hospitals_tail = apollo_hospitals.tail(15)
    apollo_hospitals_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1, inplace=True)
    apollo_hospitals_tail.reset_index(inplace=True)

    apollo_hospitals.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    apollo_hospitals.reset_index(inplace=True)
    data = apollo_hospitals[["Date","Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future= fbp.make_future_dataframe(periods=365)
    forecast=fbp.predict(future)

    from fbprophet.plot import plot_plotly
    fig=plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("apollo_hospitals.html",graphJSON=graphJSON,
                           tables=[apollo_hospitals_tail.to_html(classes='apollohospitals',index=False)] )


@app.route("/search/asian_paints")
@login_required
def asian_paints():
    asian_paints = get_history(symbol="ASIANPAINT",
                              start=date(2000, 1, 1),
                              end=date.today())
    asian_paints_tails = asian_paints.tail(15)
    asian_paints_tails.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1, inplace=True)
    asian_paints_tails.reset_index(inplace=True)

    asian_paints.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    asian_paints.reset_index(inplace=True)
    data = asian_paints[["Date","Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future= fbp.make_future_dataframe(periods=365)
    forecast=fbp.predict(future)

    from fbprophet.plot import plot_plotly
    fig=plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("asian_paints.html",graphJSON=graphJSON,
                           tables=[asian_paints_tails.to_html(classes='asianpaints',index=False)] )


@app.route("/search/axis_bank")
@login_required
def axis_bank():
    axis_bank = get_history(symbol="AXISBANK",
                              start=date(2000, 1, 1),
                              end=date.today())
    axis_bank_tail = axis_bank.tail(15)
    axis_bank_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1, inplace=True)
    axis_bank_tail.reset_index(inplace=True)

    axis_bank.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    axis_bank.reset_index(inplace=True)
    data = axis_bank[["Date","Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future= fbp.make_future_dataframe(periods=365)
    forecast=fbp.predict(future)

    from fbprophet.plot import plot_plotly
    fig=plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("axis_bank.html",graphJSON=graphJSON,
                           tables=[axis_bank_tail.to_html(classes='axisbank',index=False)] )


@app.route("/search/bajaj_auto")
@login_required
def bajaj_auto():
    bajaj_auto = get_history(symbol="BAJAJ-AUTO",
                              start=date(2000, 1, 1),
                              end=date.today())
    bajaj_auto_tail = bajaj_auto.tail(15)
    bajaj_auto_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    bajaj_auto_tail.reset_index(inplace=True)

    bajaj_auto.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    bajaj_auto.reset_index(inplace=True)
    data = bajaj_auto[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("bajaj_auto.html", graphJSON=graphJSON,
                           tables=[bajaj_auto_tail.to_html(classes='bajajauto', index=False)])


@app.route("/search/bajaj_finance")
@login_required
def bajaj_finance():
    bajaj_finance = get_history(symbol="BAJFINANCE",
                              start=date(2000, 1, 1),
                              end=date.today())
    bajaj_finance_tail = bajaj_finance.tail(15)
    bajaj_finance_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    bajaj_finance_tail.reset_index(inplace=True)

    bajaj_finance.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    bajaj_finance.reset_index(inplace=True)
    data = bajaj_finance[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("bajaj_finance.html", graphJSON=graphJSON,
                           tables=[bajaj_finance_tail.to_html(classes='bajajfinance', index=False)])


@app.route("/search/bajaj_finserv")
@login_required
def bajaj_finserv():
    bajaj_finserv = get_history(symbol="BAJAJFINSV",
                              start=date(2000, 1, 1),
                              end=date.today())
    bajaj_finserv_tail = bajaj_finserv.tail(15)
    bajaj_finserv_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    bajaj_finserv_tail.reset_index(inplace=True)

    bajaj_finserv.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    bajaj_finserv.reset_index(inplace=True)
    data = bajaj_finserv[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("bajaj_finserv.html", graphJSON=graphJSON,
                           tables=[bajaj_finserv_tail.to_html(classes='bajajfinserv', index=False)])



@app.route("/search/bharat_petroleum")
@login_required
def bharat_petroleum():
    bpcl = get_history(symbol="BPCL",
                              start=date(2000, 1, 1),
                              end=date.today())
    bpcl_tail = bpcl.tail(15)
    bpcl_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    bpcl_tail.reset_index(inplace=True)

    bpcl.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    bpcl.reset_index(inplace=True)
    data = bpcl[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("bharat_petroleum.html", graphJSON=graphJSON,
                           tables=[bpcl_tail.to_html(classes='bpcl', index=False)])



@app.route("/search/bharti_airtel")
@login_required
def airtel():
    airtel = get_history(symbol="BHARTIARTL",
                              start=date(2000, 1, 1),
                              end=date.today())
    airtel_tail = airtel.tail(15)
    airtel_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    airtel_tail.reset_index(inplace=True)

    airtel.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    airtel.reset_index(inplace=True)
    data = airtel[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("bharti_airtel.html", graphJSON=graphJSON,
                           tables=[airtel_tail.to_html(classes='airtel', index=False)])


@app.route("/search/britannia")
@login_required
def britannia():
    britannia = get_history(symbol="BRITANNIA",
                              start=date(2000, 1, 1),
                              end=date.today())
    britannia_tail = britannia.tail(15)
    britannia_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    britannia_tail.reset_index(inplace=True)

    britannia.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    britannia.reset_index(inplace=True)
    data = britannia[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("britannia.html", graphJSON=graphJSON,
                           tables=[britannia_tail.to_html(classes='britannia', index=False)])


@app.route("/search/cipla")
@login_required
def cipla():
    cipla = get_history(symbol="CIPLA",
                              start=date(2000, 1, 1),
                              end=date.today())
    cipla_tail = cipla.tail(15)
    cipla_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    cipla_tail.reset_index(inplace=True)

    cipla.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    cipla.reset_index(inplace=True)
    data = cipla[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("cipla.html", graphJSON=graphJSON,
                           tables=[cipla_tail.to_html(classes='cipla', index=False)])


@app.route("/search/coal_india")
@login_required
def coal_india():
    coal_india = get_history(symbol="COALINDIA",
                              start=date(2000, 1, 1),
                              end=date.today())
    coal_india_tail = coal_india.tail(15)
    coal_india_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    coal_india_tail.reset_index(inplace=True)

    coal_india.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    coal_india.reset_index(inplace=True)
    data = coal_india[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("coal_india.html", graphJSON=graphJSON,
                           tables=[coal_india_tail.to_html(classes='coalindia', index=False)])



@app.route("/search/divis_lab")
@login_required
def divis_lab():
    divis_lab = get_history(symbol="DIVISLAB",
                              start=date(2000, 1, 1),
                              end=date.today())
    divis_lab_tail = divis_lab.tail(15)
    divis_lab_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    divis_lab_tail.reset_index(inplace=True)

    divis_lab.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    divis_lab.reset_index(inplace=True)
    data = divis_lab[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("divis_lab.html", graphJSON=graphJSON,
                           tables=[divis_lab_tail.to_html(classes='divislab', index=False)])


@app.route("/search/drreddy_labs")
@login_required
def drreddy_labs():
    drreddy_labs = get_history(symbol="DRREDDY",
                              start=date(2000, 1, 1),
                              end=date.today())
    drreddy_labs_tail = drreddy_labs.tail(15)
    drreddy_labs_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    drreddy_labs_tail.reset_index(inplace=True)

    drreddy_labs.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    drreddy_labs.reset_index(inplace=True)
    data = drreddy_labs[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("drreddy_labs.html", graphJSON=graphJSON,
                           tables=[drreddy_labs_tail.to_html(classes='drreddy', index=False)])



@app.route("/search/eicher_motors")
@login_required
def eicher_motors():
    eicher_motors = get_history(symbol="EICHERMOT",
                              start=date(2000, 1, 1),
                              end=date.today())
    eicher_motors_tail = eicher_motors.tail(15)
    eicher_motors_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    eicher_motors_tail.reset_index(inplace=True)

    eicher_motors.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    eicher_motors.reset_index(inplace=True)
    data = eicher_motors[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("eicher_motors.html", graphJSON=graphJSON,
                           tables=[eicher_motors_tail.to_html(classes='eichermotors', index=False)])


@app.route("/search/grasim_industries")
@login_required
def grasim_industries():
    grasim_industries = get_history(symbol="GRASIM",
                              start=date(2000, 1, 1),
                              end=date.today())
    grasim_industries_tail = grasim_industries.tail(15)
    grasim_industries_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    grasim_industries_tail.reset_index(inplace=True)

    grasim_industries.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    grasim_industries.reset_index(inplace=True)
    data = grasim_industries[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("grasim_industries.html", graphJSON=graphJSON,
                           tables=[grasim_industries_tail.to_html(classes='grasim', index=False)])


@app.route("/search/hcl_tech")
@login_required
def hcl_tech():
    hcl_tech = get_history(symbol="HCLTECH",
                              start=date(2000, 1, 1),
                              end=date.today())
    hcl_tech_tail = hcl_tech.tail(15)
    hcl_tech_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    hcl_tech_tail.reset_index(inplace=True)

    hcl_tech.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    hcl_tech.reset_index(inplace=True)
    data = hcl_tech[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("hcl_tech.html", graphJSON=graphJSON,
                           tables=[hcl_tech_tail.to_html(classes='hcltech', index=False)])



@app.route("/search/hdfc")
@login_required
def hdfc():
    hdfc = get_history(symbol="HDFC",
                              start=date(2000, 1, 1),
                              end=date.today())
    hdfc_tail = hdfc.tail(15)
    hdfc_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    hdfc_tail.reset_index(inplace=True)

    hdfc.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    hdfc.reset_index(inplace=True)
    data = hdfc[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("hdfc.html", graphJSON=graphJSON,
                           tables=[hdfc_tail.to_html(classes='hdfc', index=False)])



@app.route("/search/hdfc_bank")
@login_required
def hdfc_bank():
    hdfc_bank = get_history(symbol="HDFCBANK",
                              start=date(2000, 1, 1),
                              end=date.today())
    hdfc_bank_tail = hdfc_bank.tail(15)
    hdfc_bank_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    hdfc_bank_tail.reset_index(inplace=True)

    hdfc_bank.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    hdfc_bank.reset_index(inplace=True)
    data = hdfc_bank[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("hdfc_bank.html", graphJSON=graphJSON,
                           tables=[hdfc_bank_tail.to_html(classes='hdfcbank', index=False)])



@app.route("/search/hdfc_life")
@login_required
def hdfc_life():
    hdfc_life = get_history(symbol="HDFCLIFE",
                              start=date(2000, 1, 1),
                              end=date.today())
    hdfc_life_tail = hdfc_life.tail(15)
    hdfc_life_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    hdfc_life_tail.reset_index(inplace=True)

    hdfc_life.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    hdfc_life.reset_index(inplace=True)
    data = hdfc_life[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("hdfc_life.html", graphJSON=graphJSON,
                           tables=[hdfc_life_tail.to_html(classes='hdfclife', index=False)])


@app.route("/search/hero_motocorp")
@login_required
def hero_motocorp():
    hero_motocorp = get_history(symbol="HEROMOTOCO",
                              start=date(2000, 1, 1),
                              end=date.today())
    hero_motocorp_tail = hero_motocorp.tail(15)
    hero_motocorp_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    hero_motocorp_tail.reset_index(inplace=True)

    hero_motocorp.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    hero_motocorp.reset_index(inplace=True)
    data = hero_motocorp[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("hero_motocorp.html", graphJSON=graphJSON,
                           tables=[hero_motocorp_tail.to_html(classes='heromotocorp', index=False)])


@app.route("/search/hindalco_industries")
@login_required
def hindalco_industries():
    hindalco_industries = get_history(symbol="HINDALCO",
                              start=date(2000, 1, 1),
                              end=date.today())
    hindalco_industries_tail = hindalco_industries.tail(15)
    hindalco_industries_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    hindalco_industries_tail.reset_index(inplace=True)

    hindalco_industries.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    hindalco_industries.reset_index(inplace=True)
    data = hindalco_industries[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("hindalco_industries.html", graphJSON=graphJSON,
                           tables=[hindalco_industries_tail.to_html(classes='hindalco', index=False)])



@app.route("/search/hul")
@login_required
def hul():
    hul = get_history(symbol="HINDUNILVR",
                              start=date(2000, 1, 1),
                              end=date.today())
    hul_tail = hul.tail(15)
    hul_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    hul_tail.reset_index(inplace=True)

    hul.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    hul.reset_index(inplace=True)
    data = hul[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("hul.html", graphJSON=graphJSON,
                           tables=[hul_tail.to_html(classes='hul', index=False)])



@app.route("/search/icici_bank")
@login_required
def icici_bank():
    icici_bank = get_history(symbol="ICICIBANK",
                              start=date(2000, 1, 1),
                              end=date.today())
    icici_bank_tail = icici_bank.tail(15)
    icici_bank_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    icici_bank_tail.reset_index(inplace=True)

    icici_bank.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    icici_bank.reset_index(inplace=True)
    data = icici_bank[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("icici_bank.html", graphJSON=graphJSON,
                           tables=[icici_bank_tail.to_html(classes='icicibank', index=False)])


@app.route("/search/itc_ltd")
@login_required
def itc():
    itc = get_history(symbol="ITC",
                              start=date(2000, 1, 1),
                              end=date.today())
    itc_tail = itc.tail(15)
    itc_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    itc_tail.reset_index(inplace=True)

    itc.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    itc.reset_index(inplace=True)
    data = itc[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("itc_ltd.html", graphJSON=graphJSON,
                           tables=[itc_tail.to_html(classes='itc', index=False)])


@app.route("/search/induslnd_bank")
@login_required
def induslnd_bank():
    induslnd_bank = get_history(symbol="INDUSINDBK",
                              start=date(2000, 1, 1),
                              end=date.today())
    induslnd_bank_tail = induslnd_bank.tail(15)
    induslnd_bank_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    induslnd_bank_tail.reset_index(inplace=True)

    induslnd_bank.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    induslnd_bank.reset_index(inplace=True)
    data = induslnd_bank[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("induslnd_bank.html", graphJSON=graphJSON,
                           tables=[induslnd_bank_tail.to_html(classes='induslnd', index=False)])


@app.route("/search/infosys_ltd")
@login_required
def infosys():
    infosys = get_history(symbol="INFY",
                              start=date(2000, 1, 1),
                              end=date.today())
    infosys_tail = infosys.tail(15)
    infosys_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    infosys_tail.reset_index(inplace=True)

    infosys.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    infosys.reset_index(inplace=True)
    data = infosys[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("infosys_ltd.html", graphJSON=graphJSON,
                           tables=[infosys_tail.to_html(classes='infosys', index=False)])


@app.route("/search/jsw_steel")
@login_required
def jsw_steel():
    jsw_steel = get_history(symbol="JSWSTEEL",
                              start=date(2000, 1, 1),
                              end=date.today())
    jsw_steel_tail = jsw_steel.tail(15)
    jsw_steel_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    jsw_steel_tail.reset_index(inplace=True)

    jsw_steel.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    jsw_steel.reset_index(inplace=True)
    data = jsw_steel[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("jsw_steel.html", graphJSON=graphJSON,
                           tables=[jsw_steel_tail.to_html(classes='jswsteel', index=False)])


@app.route("/search/kotak_mahindra")
@login_required
def kotak_mahindra():
    kotak_mahindra = get_history(symbol="JSWSTEEL",
                              start=date(2000, 1, 1),
                              end=date.today())
    kotak_mahindra_tail = kotak_mahindra.tail(15)
    kotak_mahindra_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    kotak_mahindra_tail.reset_index(inplace=True)

    kotak_mahindra.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    kotak_mahindra.reset_index(inplace=True)
    data = kotak_mahindra[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("kotak_mahindra.html", graphJSON=graphJSON,
                           tables=[kotak_mahindra_tail.to_html(classes='kotakmahindra', index=False)])

@app.route("/search/larsen_toubro")
@login_required
def lnt():
    lnt = get_history(symbol="LT",
                              start=date(2000, 1, 1),
                              end=date.today())
    lnt_tail = lnt.tail(15)
    lnt_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    lnt_tail.reset_index(inplace=True)

    lnt.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    lnt.reset_index(inplace=True)
    data = lnt[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("larsen_toubro.html", graphJSON=graphJSON,
                           tables=[lnt_tail.to_html(classes='larsentoubro', index=False)])

@app.route("/search/mahindra_auto")
@login_required
def mahindra_auto():
    mahindra_auto = get_history(symbol="M&M",
                              start=date(2000, 1, 1),
                              end=date.today())
    mahindra_auto_tail = mahindra_auto.tail(15)
    mahindra_auto_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    mahindra_auto_tail.reset_index(inplace=True)

    mahindra_auto.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    mahindra_auto.reset_index(inplace=True)
    data = mahindra_auto[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("mahindra_auto.html", graphJSON=graphJSON,
                           tables=[mahindra_auto_tail.to_html(classes='m&m', index=False)])


@app.route("/search/maruti_suzuki")
@login_required
def maruti_suzuki():
    maruti_suzuki = get_history(symbol="MARUTI",
                              start=date(2000, 1, 1),
                              end=date.today())
    maruti_suzuki_tail = maruti_suzuki.tail(15)
    maruti_suzuki_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    maruti_suzuki_tail.reset_index(inplace=True)

    maruti_suzuki.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    maruti_suzuki.reset_index(inplace=True)
    data = maruti_suzuki[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("maruti_suzuki.html", graphJSON=graphJSON,
                           tables=[maruti_suzuki_tail.to_html(classes='marutisuzuki', index=False)])


@app.route("/search/ntpc_ltd")
@login_required
def ntpc():
    ntpc = get_history(symbol="NTPC",
                              start=date(2000, 1, 1),
                              end=date.today())
    ntpc_tail = ntpc.tail(15)
    ntpc_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    ntpc_tail.reset_index(inplace=True)

    ntpc.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    ntpc.reset_index(inplace=True)
    data = ntpc[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("ntpc_ltd.html", graphJSON=graphJSON,
                           tables=[ntpc_tail.to_html(classes='ntpc', index=False)])


@app.route("/search/nestle_india")
@login_required
def nestle_india():
    nestle_india = get_history(symbol="NESTLEIND",
                              start=date(2000, 1, 1),
                              end=date.today())
    nestle_india_tail = nestle_india.tail(15)
    nestle_india_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    nestle_india_tail.reset_index(inplace=True)

    nestle_india.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    nestle_india.reset_index(inplace=True)
    data = nestle_india[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("nestle_india.html", graphJSON=graphJSON,
                           tables=[nestle_india_tail.to_html(classes='nestle', index=False)])


@app.route("/search/ongc")
@login_required
def ongc():
    ongc = get_history(symbol="ONGC",
                              start=date(2000, 1, 1),
                              end=date.today())
    ongc_tail = ongc.tail(15)
    ongc_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    ongc_tail.reset_index(inplace=True)

    ongc.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    ongc.reset_index(inplace=True)
    data = ongc[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("ongc.html", graphJSON=graphJSON,
                           tables=[ongc_tail.to_html(classes='ongc', index=False)])


@app.route("/search/power_grid")
@login_required
def power_grid():
    power_grid = get_history(symbol="POWERGRID",
                              start=date(2000, 1, 1),
                              end=date.today())
    power_grid_tail = power_grid.tail(15)
    power_grid_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    power_grid_tail.reset_index(inplace=True)

    power_grid.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    power_grid.reset_index(inplace=True)
    data = power_grid[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("power_grid.html", graphJSON=graphJSON,
                           tables=[power_grid_tail.to_html(classes='powergrid', index=False)])


@app.route("/search/reliance_industries")
@login_required
def reliance():
    reliance = get_history(symbol="RELIANCE",
                              start=date(2000, 1, 1),
                              end=date.today())
    reliance_tail = reliance.tail(15)
    reliance_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    reliance_tail.reset_index(inplace=True)

    reliance.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    reliance.reset_index(inplace=True)
    data = reliance[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("reliance_industries.html", graphJSON=graphJSON,
                           tables=[reliance_tail.to_html(classes='reliance', index=False)])


@app.route("/search/sbi_life")
@login_required
def sbi_life():
    sbi_life = get_history(symbol="SBILIFE",
                              start=date(2000, 1, 1),
                              end=date.today())
    sbi_life_tail =sbi_life.tail(15)
    sbi_life_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    sbi_life_tail.reset_index(inplace=True)

    sbi_life.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    sbi_life.reset_index(inplace=True)
    data = sbi_life[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("sbi_life.html", graphJSON=graphJSON,
                           tables=[sbi_life_tail.to_html(classes='sbilife', index=False)])


@app.route("/search/shree_cement")
@login_required
def shree_cement():
    shree_cement = get_history(symbol="SHREECEM",
                              start=date(2000, 1, 1),
                              end=date.today())
    shree_cement_tail =shree_cement.tail(15)
    shree_cement_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    shree_cement_tail.reset_index(inplace=True)

    shree_cement.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    shree_cement.reset_index(inplace=True)
    data = shree_cement[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("shree_cement.html", graphJSON=graphJSON,
                           tables=[shree_cement_tail.to_html(classes='shreecement', index=False)])


@app.route("/search/state_bank_india")
@login_required
def sbi():
    sbi = get_history(symbol="SBIN",
                              start=date(2000, 1, 1),
                              end=date.today())
    sbi_tail =sbi.tail(15)
    sbi_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    sbi_tail.reset_index(inplace=True)

    sbi.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    sbi.reset_index(inplace=True)
    data = sbi[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("state_bank_india.html", graphJSON=graphJSON,
                           tables=[sbi_tail.to_html(classes='sbi', index=False)])


@app.route("/search/sun_pharma")
@login_required
def sun_pharma():
    sun_pharma = get_history(symbol="SUNPHARMA",
                              start=date(2000, 1, 1),
                              end=date.today())
    sun_pharma_tail =sun_pharma.tail(15)
    sun_pharma_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    sun_pharma_tail.reset_index(inplace=True)

    sun_pharma.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    sun_pharma.reset_index(inplace=True)
    data = sun_pharma[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("sun_pharma.html", graphJSON=graphJSON,
                           tables=[sun_pharma_tail.to_html(classes='sunpharma', index=False)])


@app.route("/search/tcs")
@login_required
def tcs():
    tcs = get_history(symbol="TCS",
                              start=date(2000, 1, 1),
                              end=date.today())
    tcs_tail =tcs.tail(15)
    tcs_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    tcs_tail.reset_index(inplace=True)

    tcs.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    tcs.reset_index(inplace=True)
    data = tcs[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("tcs.html", graphJSON=graphJSON,
                           tables=[tcs_tail.to_html(classes='tcs', index=False)])


@app.route("/search/tata_consumer")
@login_required
def tata_consumer():
    tata_consumer = get_history(symbol="TATACONSUM",
                              start=date(2000, 1, 1),
                              end=date.today())
    tata_consumer_tail =tata_consumer.tail(15)
    tata_consumer_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    tata_consumer_tail.reset_index(inplace=True)

    tata_consumer.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    tata_consumer.reset_index(inplace=True)
    data = tata_consumer[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("tata_consumer.html", graphJSON=graphJSON,
                           tables=[tata_consumer_tail.to_html(classes='tataconsumer', index=False)])


@app.route("/search/tata_motors")
@login_required
def tata_motors():
    tata_motors = get_history(symbol="TATAMOTORS",
                              start=date(2000, 1, 1),
                              end=date.today())
    tata_motors_tail =tata_motors.tail(15)
    tata_motors_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    tata_motors_tail.reset_index(inplace=True)

    tata_motors.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    tata_motors.reset_index(inplace=True)
    data = tata_motors[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("tata_motors.html", graphJSON=graphJSON,
                           tables=[tata_motors_tail.to_html(classes='tatamotors', index=False)])


@app.route("/search/tata_steel")
@login_required
def tata_steel():
    tata_steel = get_history(symbol="TATASTEEL",
                              start=date(2000, 1, 1),
                              end=date.today())
    tata_steel_tail =tata_steel.tail(15)
    tata_steel_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    tata_steel_tail.reset_index(inplace=True)

    tata_steel.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    tata_steel.reset_index(inplace=True)
    data = tata_steel[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("tata_steel.html", graphJSON=graphJSON,
                           tables=[tata_steel_tail.to_html(classes='tatasteel', index=False)])


@app.route("/search/tech_mahindra")
@login_required
def tech_mahindra():
    tech_mahindra = get_history(symbol="TECHM",
                              start=date(2000, 1, 1),
                              end=date.today())
    tech_mahindra_tail =tech_mahindra.tail(15)
    tech_mahindra_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    tech_mahindra_tail.reset_index(inplace=True)

    tech_mahindra.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    tech_mahindra.reset_index(inplace=True)
    data = tech_mahindra[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("tech_mahindra.html", graphJSON=graphJSON,
                           tables=[tech_mahindra_tail.to_html(classes='techmahindra', index=False)])



@app.route("/search/titan_company")
@login_required
def titan():
    titan = get_history(symbol="TITAN ",
                              start=date(2000, 1, 1),
                              end=date.today())
    titan_tail =titan.tail(15)
    titan_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    titan_tail.reset_index(inplace=True)

    titan.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    titan.reset_index(inplace=True)
    data = titan[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("titan_company.html", graphJSON=graphJSON,
                           tables=[titan_tail.to_html(classes='titan', index=False)])


@app.route("/search/upl_ltd")
@login_required
def upl():
    upl = get_history(symbol="UPL",
                              start=date(2000, 1, 1),
                              end=date.today())
    upl_tail =upl.tail(15)
    upl_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    upl_tail.reset_index(inplace=True)

    upl.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    upl.reset_index(inplace=True)
    data = upl[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("upl_ltd.html", graphJSON=graphJSON,
                           tables=[upl_tail.to_html(classes='upl', index=False)])


@app.route("/search/ultratech_cement")
@login_required
def ultratech_cement():
    ultratech_cement = get_history(symbol="ULTRACEMCO",
                              start=date(2000, 1, 1),
                              end=date.today())
    ultratech_cement_tail =ultratech_cement.tail(15)
    ultratech_cement_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    ultratech_cement_tail.reset_index(inplace=True)

    ultratech_cement.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
               inplace=True)
    ultratech_cement.reset_index(inplace=True)
    data = ultratech_cement[["Date", "Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future = fbp.make_future_dataframe(periods=365)
    forecast = fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig = plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("ultratech_cement.html", graphJSON=graphJSON,
                           tables=[ultratech_cement_tail.to_html(classes='ultratechcement', index=False)])


@app.route("/search/wipro")
@login_required
def wipro():
    wipro = get_history(symbol="WIPRO",
                              start=date(2000, 1, 1),
                              end=date.today())
    wipro_tail = wipro.tail(15)
    wipro_tail.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1, inplace=True)
    wipro_tail.reset_index(inplace=True)

    wipro.drop(['Symbol', 'Series', 'Turnover', '%Deliverble', 'Trades', 'Deliverable Volume'], axis=1,
                    inplace=True)
    wipro.reset_index(inplace=True)
    data = wipro[["Date","Close"]]
    data = data.rename(columns={"Date": "ds", "Close": "y"})

    fbp = Prophet(daily_seasonality=True)
    fbp.fit(data)
    future= fbp.make_future_dataframe(periods=365)
    forecast=fbp.predict(future)
    from fbprophet.plot import plot_plotly
    fig=plot_plotly(fbp, forecast)
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template("wipro.html",graphJSON=graphJSON,tables=[wipro_tail.to_html(classes='wipro',index=False)] )



if __name__ == '__main__':
    app.run(debug=True)

