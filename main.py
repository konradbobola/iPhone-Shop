#___________________________________________import bibliotek___________________________________________
#flask
from flask import Flask, render_template, flash, redirect, url_for
#email
import smtplib
#bootstrap
from flask_bootstrap import Bootstrap
# flask wtf
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, RadioField, IntegerField, FloatField, TextAreaField
from wtforms.validators import DataRequired, Email, ValidationError
#sql alchemy
from flask_sqlalchemy import SQLAlchemy
#flask login
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
# werkzeug
from werkzeug.security import generate_password_hash, check_password_hash
#flask login
login_manager = LoginManager()
#seller decorator
from functools import wraps
from flask import abort


app = Flask(__name__)
Bootstrap(app)
login_manager.init_app(app)

#email
OWN_EMAIL = "iphoneshopagh@gmail.com"
OWN_PASSWORD = "seiczbwqnhorxarj"

#wtf form
app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


#___________________________________________Klasy-db.Model___________________________________________
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(1000))
    surname = db.Column(db.String(1000))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    role = db.Column(db.String(1000))

    products = db.relationship('PozycjaKoszyk', backref='user')

    order = db.relationship("Order", back_populates="user")

    def __init__(self, firstname, surname, email, password, role):
        self.email = email
        self.firstname = firstname
        self.surname = surname
        self.password = password
        self.role = role


class Iphone(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    model = db.Column(db.String(100))
    price = db.Column(db.Float)
    display = db.Column(db.String(100))
    ram = db.Column(db.Integer)
    memory = db.Column(db.Integer)
    camera = db.Column(db.Integer)
    description = db.Column(db.String(1000))
    path = db.Column(db.String(1000))

    def __init__(self, model, price, display, ram, memory, camera, description, path):
        self.model = model
        self.price = price
        self.display = display
        self.ram = ram
        self.memory = memory
        self.camera = camera
        self.description = description
        self.path = path

    def __repr__(self):
        return f" {self.id}, {self.model}"


class PozycjaKoszyk(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_iphone = db.Column(db.Integer, db.ForeignKey('iphone.id'))
    id_uzykownika = db.Column(db.Integer, db.ForeignKey('user.id'))

    iphone = db.relationship('Iphone', backref='pozycjakoszyk')

    def __init__(self,  id_iphone, id_uzytkownika):
        self.id_iphone = id_iphone
        self.id_uzykownika = id_uzytkownika

    def __repr__(self):
        return f" {self.id}"


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    iphones = db.Column(db.String(1000))
    id_uzytkownika = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(100))
    street = db.Column(db.String(100))
    zip_code = db.Column(db.String(100))
    apartment_no = db.Column(db.String(100))
    method = db.Column(db.String(100))
    notes = db.Column(db.String(100))
    price = db.Column(db.Float)

    user = db.relationship("User", back_populates="order")

    def __init__(self, iphones, id_uzykownika, status, street, zip_code, apartment_no, method, notes, price):
        self.iphones = iphones
        self.id_uzytkownika = id_uzykownika
        self.status = status
        self.street = street
        self.zip_code = zip_code
        self.apartment_no = apartment_no
        self.method = method
        self.notes = notes
        self.price = price

#___________________________________________funkcje___________________________________________


def my_length_check(form, field):
    if len(field.data) < 8:
        raise ValidationError('password must be more than 8 characters')


def seller_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'Seller':
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


def send_email(email, title, phone, message):
    email_message = f"Subject:Support\n\nEmail: {email}\nTitle: {title}\nPhone: {phone}\nMessage:{message}"
    with smtplib.SMTP("smtp.gmail.com", 587, timeout=120) as connection:
        connection.starttls()
        connection.login(OWN_EMAIL, OWN_PASSWORD)
        connection.sendmail(OWN_EMAIL, OWN_EMAIL, email_message)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#___________________________________________Klasy-Form___________________________________________
class RegisterForm(FlaskForm):
    firstname = StringField('first name', validators=[DataRequired()])
    surname = StringField('surname', validators=[DataRequired()])
    email = StringField('email', validators=[DataRequired(), Email(None, True, True, True, True), my_length_check])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField("Log in")


class ContactForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Email(None, True, True, True, True), my_length_check])
    phone = StringField('phone', validators=[DataRequired()])
    title2 = StringField('title', validators=[DataRequired()])
    message = TextAreaField('message', validators=[DataRequired()])
    submit = SubmitField("Send")


class OrderForm(FlaskForm):
    street = StringField('Street', validators=[DataRequired()])
    zip_code = StringField('Zip Code', validators=[DataRequired()])
    apartment_no = StringField('Apartment Number', validators=[DataRequired()])
    notes = StringField('notes', validators=[DataRequired()])
    method = RadioField('Choose your delivery method ', choices=[('Cash on delivery', 'Cash on delivery'), ('Personal Pickup','Personal Pickup')])
    submit = SubmitField("Confirm Order")


class IphoneForm(FlaskForm):
    model = StringField('model', validators=[DataRequired()])
    price = FloatField('price', validators=[DataRequired()])
    display = StringField('display', validators=[DataRequired()])
    ram = IntegerField('ram', validators=[DataRequired()])
    memory = IntegerField('memory', validators=[DataRequired()])
    camera = IntegerField('camera', validators=[DataRequired()])
    description = StringField('description', validators=[DataRequired()])
    path = StringField('path', validators=[DataRequired()])
    submit = SubmitField("add iPhone")


class ChangeStatusForm(FlaskForm):
    status = RadioField('Change status order', choices=[('waiting', 'waiting'), ('ready','ready'), ('cancelled', 'cancelled')], )
    submit = SubmitField("Confirm ")


#___________________________________________app.routr___________________________________________
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/contact', methods=["GET", "POST"])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        email = form.email.data
        phone = form.phone.data
        title = form.title2.data
        message = form.message.data
        send_email(email, title, phone, message)
        return render_template("contact.html", form=form, msg_sent=True)
    return render_template("contact.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        if User.query.filter_by(email=email).first():
            user = User.query.filter_by(email=email).first()
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=True)
                flash("Success!")
                return render_template("login.html", form=form)
            else:
                flash('bad password')
                return render_template('login.html', form=form)
        else:
            flash('Email not found')

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        firstname = form.firstname.data
        surname = form.surname.data
        email = form.email.data
        password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=5)
        if not User.query.filter_by(email=email).first():
            new_user = User(firstname, surname, email, password, "User")
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            return redirect("available_models")
        else:
            flash("You've already signed up with that email, log in instead!")
            return redirect('login')

    return render_template("register.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/available_models')
def available_models():
    iphones = db.session.query(Iphone)
    return render_template("available_models.html", iphones=iphones)


@app.route('/description/<int:id>')
def description(id):
    print(id)
    iphone = Iphone.query.get(id)
    print(iphone)
    return render_template('description.html', iphone=iphone, current_user=current_user)


@app.route('/buy/<int:id>')
@login_required
def buy(id):
    iphone = Iphone.query.get(id)
    pozycja_koszyk = PozycjaKoszyk(iphone.id, current_user.id)
    db.session.add(pozycja_koszyk)
    db.session.commit()
    return redirect(url_for('koszyk'))


@app.route('/koszyk')
@login_required
def koszyk():
    # wyswietlenie wszytskich produktow danego uzytkownika
    user = User.query.get(current_user.id)
    pozycje = user.products
    do_zaplaty = 0
    for pozycja in pozycje:
        # odwolanie do pozycja.iphone.model i pozycja.iphone.price
        do_zaplaty += pozycja.iphone.price

    return render_template('koszyk.html', pozycje=pozycje, do_zaplaty=do_zaplaty)


@app.route('/delete/<int:id>')
@login_required
def delete(id):
    pozycja = PozycjaKoszyk.query.get(id)
    print(pozycja)
    db.session.delete(pozycja)
    db.session.commit()

    return redirect(url_for('koszyk'))


@app.route('/order', methods=['GET', 'POST'])
@login_required
def order():
    form = OrderForm()

    user = User.query.get(current_user.id)
    pozycje = user.products
    price = 0
    iphones_lista = []
    for pozycja in pozycje:
        # odwolanie do pozycja.iphone.model i pozycja.iphone.price
        price += pozycja.iphone.price
        iphones_lista += f'{pozycja.iphone.model}, '

    iphone_string = ''.join(iphones_lista)

    if form.validate_on_submit():
        steet = form.street.data
        zip_code = form.zip_code.data
        apartment_no = form.apartment_no.data
        notes = form.notes.data
        method = form.method.data

        # dodanie order do bazy danych
        order = Order(iphone_string, current_user.id, 'waiting', steet, zip_code, apartment_no, method, notes, price)
        db.session.add(order)

        # Usun wszytskie pozycje gdzie id = current_user.id
        for pozycja in pozycje:
            db.session.delete(pozycja)

        db.session.commit()

        return redirect(url_for('index'))

    return render_template("order.html", form=form, do_zaplaty=price)


@app.route('/userorder')
@login_required
def userorder():
    orders = Order.query.filter(Order.id_uzytkownika == current_user.id).all()

    return render_template("user_order.html", orders=orders)


@app.route("/add_iphone", methods=["GET", "POST"])
@seller_only
def add_iphone():
    form = IphoneForm()
    if form.validate_on_submit():
        model = form.model.data
        price = form.price.data
        display = form.display.data
        ram = form.ram.data
        memory = form.memory.data
        camera = form.memory.data
        description = form.description.data
        path = form.path.data

        iphone = Iphone(model, price, display, ram, memory, camera, description, path)
        db.session.add(iphone)
        db.session.commit()
        return redirect(url_for("add_iphone"))

    return render_template("add_iphone.html", form=form, current_user=current_user)


@app.route("/all_iphones")
@seller_only
def all_iphones():
    iphones = db.session.query(Iphone)
    return render_template("all_iphones.html", iphones=iphones, current_user=current_user)


@seller_only
@app.route("/delete_iphone/<int:id>")
def delete_iphone(id):
    iphone_to_be_deleted = Iphone.query.get(id)
    db.session.delete(iphone_to_be_deleted)
    db.session.commit()
    return redirect(url_for('all_iphones'))


@seller_only
@app.route("/all_orders")
def all_orders():
    orders = db.session.query(Order)

    return render_template("all_orders.html", orders=orders, current_user=current_user)


@app.route("/change_order_status/<int:id>", methods=["GET", "POST"])
@seller_only
def change_order_status(id):
    order = Order.query.get(id)
    form = ChangeStatusForm()
    if form.validate_on_submit():
        status = form.status.data
        order.status = status
        db.session.commit()
        return redirect(url_for('all_orders'))

    return render_template("change_order_status.html", form=form, order=order, current_user=current_user)


@app.route("/delete_order/<int:id>")
@seller_only
def delete_order(id):
    order = Order.query.get(id)
    db.session.delete(order)
    db.session.commit()
    return redirect(url_for('all_orders'))

    return render_template("closed_orders.html")


if __name__ == "__main__":
    app.run(debug=True)