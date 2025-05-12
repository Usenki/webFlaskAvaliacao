from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = 'IFSC2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    contacts = db.relationship('Contact', backref='user', lazy=True)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    messages = db.relationship('Message', backref='contact', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    text = db.Column(db.Text, nullable=False)
    date_sent = db.Column(db.DateTime, default=datetime.now)
    contact_id = db.Column(db.Integer, db.ForeignKey('contact.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET'])
@login_required
def home():
    contacts = Contact.query.filter_by(user_id=current_user.id).all()
    return render_template('home.html', contacts=contacts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Usuário não existe!')
            return redirect(url_for('login'))
        if not check_password_hash(user.password, password):
            flash("Senha inválida!")
            return redirect(url_for('login'))
        
        login_user(user)
        return redirect(url_for('home'))
        
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password1 = request.form['password1']
        password2 = request.form['password2']
        erros = []
        if len(name) < 2:
            erros.append('Nome deve ter pelo menos 2 caracteres')
        if  email.find('@') == -1:
            erros.append('Email inválido')
        if len(password1) < 8:
            erros.append('A senha deve ter pelo menos 8 caracteres')
        if password1 != password2:
            erros.append('As senhas devem ser iguais')
        
        if len(erros) > 0:
            return render_template('signup.html', erros=erros, name=name, email=email)
        else:
            senha_hash = generate_password_hash(password1)
            user = User(name=name, email=email, password=senha_hash)
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('home'))
    
    return render_template('signup.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/add_contact_page', methods=['GET'])
@login_required
def add_contact_page():
    return render_template('add_contact.html')


@app.route('/add_contact', methods=['POST'])
@login_required
def add_contact():
    name = request.form['name']
    email = request.form['email']
    phone = request.form['phone']
    contact = Contact(name=name, email=email, phone=phone, user_id=current_user.id)
    db.session.add(contact)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/edit_contact_page/<int:contact_id>', methods=['GET', 'POST'])
@login_required
def edit_contact_page(contact_id):
    contact = Contact.query.get_or_404(contact_id)

    if request.method == 'POST':
        contact.name = request.form['name']
        contact.email = request.form['email']
        contact.phone = request.form['phone']
        db.session.commit()
        return redirect(url_for('home'))

    return render_template('edit_contact.html', contact=contact)

@app.route('/send_message_page/<int:contact_id>', methods=['GET', 'POST'])
@login_required
def send_message_page(contact_id):
    contact = Contact.query.get_or_404(contact_id)

    if request.method == 'POST':
        title = request.form['title']
        text = request.form['text']
        message = Message(title=title, text=text, contact_id=contact.id)
        db.session.add(message)
        db.session.commit()
        return redirect(url_for('view_messages', contact_id=contact.id))

    return render_template('send_message.html', contact=contact)

@app.route('/delete_contact/<int:contact_id>', methods=['GET'])
@login_required
def delete_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)

    Message.query.filter_by(contact_id=contact.id).delete()
    db.session.delete(contact)
    db.session.commit()
    
    return redirect(url_for('home'))

@app.route('/delete_message/<int:message_id>', methods=['GET'])
@login_required
def delete_message(message_id):
    message = Message.query.get_or_404(message_id)
    db.session.delete(message)
    db.session.commit()
    
    return redirect(url_for('view_messages', contact_id=message.contact_id))


@app.route('/message/<int:contact_id>', methods=['POST'])
@login_required
def send_message(contact_id):
    title = request.form['title']
    text = request.form['text']
    message = Message(title=title, text=text, contact_id=contact_id)
    db.session.add(message)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/view_messages/<int:contact_id>', methods=['GET'])
@login_required
def view_messages(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    messages = Message.query.filter_by(contact_id=contact.id).order_by(Message.date_sent.desc()).all()

    return render_template('view_messages.html', contact=contact, messages=messages)


def create_tables():
    with app.app_context():
        db.create_all()

if __name__ == "__main__":
    create_tables()
    app.run(debug=True)
