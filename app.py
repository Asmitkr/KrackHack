from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import TextAreaField
from wtforms.validators import DataRequired

app = Flask(__name__)
app.secret_key = 'Asmit_bhoi'  # Change this to a secure random key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # SQLite database file path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)


class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('complaints', lazy=True))
    content = db.Column(db.Text, nullable=False)
    # status = db.Column(db.String(20), default='Pending', nullable=False)
    approvedByAdmin = db.Column(db.String(20),default='Pending', nullable=False)
    approvedBythree = db.Column(db.String(20),default='Pending', nullable=False)
    approvedByfour = db.Column(db.String(20),default='Pending', nullable=False)
    approvedByfive = db.Column(db.String(20),default='Pending', nullable=False)
    
    approvedBySuperAdmin = db.Column(db.String(20),default='Pending', nullable=False)
    approvedByMoreSuperAdmin = db.Column(db.String(20),default='Pending', nullable=False)



class ComplaintForm(FlaskForm):
    complaint = TextAreaField('Complaint', validators=[DataRequired()])


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def create_more_super_admin():
    # Check if the more_super_admin already exists
    more_super_admin = User.query.filter_by(username='gitesh').first()

    # If the more_super_admin doesn't exist, create it
    if not more_super_admin:
        # Hash the password
        password_hash = generate_password_hash('gitesh')

        # Create the more_super_admin user
        more_super_admin = User(username='gitesh', password_hash=password_hash, role='more_super_admin')

        # Add the more_super_admin user to the database
        db.session.add(more_super_admin)
        db.session.commit()

        print('More Super Admin account created successfully!')
    else:
        print('More Super Admin account already exists!')


@app.route('/')
def index():
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if not current_user.is_authenticated or current_user.role != 'more_super_admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        if role not in ['user', 'admin', 'super_admin', 'more_super_admin']:
            flash('Invalid role', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        else:
            password = request.form['password']
            password_hash = generate_password_hash(password)  # Generate password hash
            new_user = User(username=username, role=role, password_hash=password_hash)  # Set password hash
            db.session.add(new_user)
            db.session.commit()
            flash(f'{role.capitalize()} account created successfully', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for(user.role))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/user')
@login_required
def user():
    if current_user.role == 'user':
        form=ComplaintForm()
        complaints = Complaint.query.all()
        return render_template('user.html',form=form , complaints=complaints)
    else:
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))


@app.route('/admin')
@login_required
def admin():
    if current_user.role == 'admin':
        complaints = Complaint.query.all()
        return render_template('admin.html', complaints=complaints)
    else:
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))


@app.route('/super_admin')
@login_required
def super_admin():
    print(f'{current_user.role=}')
    if current_user.role == 'super_admin':
        complaints = Complaint.query.all()
        return render_template('super_admin.html',complaints=complaints)
    else:
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

@app.route('/three')
@login_required
def three():
    if current_user.role == 'three':
        complaints = Complaint.query.all()
        return render_template('three.html', complaints=complaints)
    
    else:
        flash('Unauthorized access 7', 'error')
        return redirect(url_for('index'))


@app.route('/four')
@login_required
def four():
    if current_user.role == 'four':
        complaints=Complaint.query.all()
        return render_template('four.html',complaints=complaints)
    else:
        flash('Unauthorized access 8', 'error')
        return redirect(url_for('index'))


@app.route('/five')
@login_required
def five():
    if current_user.role == 'five':
        complaints=Complaint.query.all()
        return render_template('five.html',complaints=complaints)
    else:
        flash('Unauthorized access 9', 'error')
        return redirect(url_for('index'))


@app.route('/more_super_admin')
@login_required
def more_super_admin():
    if current_user.role == 'more_super_admin':
        users = User.query.all()
        return render_template('more_super_admin.html', users=users)
    else:
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))


@app.route('/manage_users', methods=['POST'])
@login_required
def manage_users():
    if current_user.role != 'more_super_admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    action = request.form['action']
    username = request.form['username']

    if action == 'add':
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        else:
            role = request.form['role']
            password = request.form['password']
            password_hash = generate_password_hash(password)
            new_user = User(username=username, password_hash=password_hash, role=role)
            db.session.add(new_user)
            db.session.commit()
    elif action == 'remove':
        user_to_remove = User.query.filter_by(username=username).first()
        if user_to_remove:
            db.session.delete(user_to_remove)
            db.session.commit()
            flash('User removed successfully', 'success')
        else:
            flash('User not found', 'error')

    return redirect(url_for('more_super_admin'))


@app.route('/remove_user/<int:user_id>', methods=['GET'])
@login_required
def remove_user(user_id):
    if current_user.role != 'more_super_admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    user_to_remove = User.query.get(user_id)
    if user_to_remove:
        db.session.delete(user_to_remove)
        db.session.commit()
        flash('User removed successfully', 'success')
    else:
        flash('User not found', 'error')

    return redirect(url_for('more_super_admin'))


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    if not check_password_hash(current_user.password_hash, current_password):
        flash('Incorrect current password', 'error')
        return redirect(url_for('more_super_admin'))

    if new_password != confirm_password:
        flash('New password and confirm password do not match', 'error')
        return redirect(url_for('more_super_admin'))

    current_user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    flash('Password changed successfully', 'success')

    return redirect(url_for('more_super_admin'))


@app.route('/submit_complaint', methods=['POST'])
@login_required
def submit_complaint():
    form = ComplaintForm(request.form)
    if form.validate_on_submit():
        complaint = Complaint(user_id=current_user.id, content=form.complaint.data)
        db.session.add(complaint)
        db.session.commit()
        flash('Complaint submitted successfully', 'success')
    else:
        error_messages = "\n".join([f"{field}: {', '.join(errors)}" for field, errors in form.errors.items()])
        flash(f'Failed to submit complaint. Errors: {error_messages}', 'error')
    return redirect(url_for('user'))



@app.route('/manage_complaint/<int:complaint_id>/approve', methods=['POST'])
@login_required
def approve_complaint(complaint_id):
    print(f'inside approve {current_user.role=}')
    if current_user.role == 'admin':
        complaint = Complaint.query.get(complaint_id)
        if complaint.approvedByAdmin != 'Approved':
            complaint.approvedByAdmin = 'Approved'
            db.session.commit()
            flash('Complaint approved successfully', 'success')
            return redirect(url_for('admin'))
        else:
            flash('Complaint not found', 'error')
    elif current_user.role == 'three':
        print(f'hitting correctly')
        complaint = Complaint.query.get(complaint_id)
        if (complaint.approvedByAdmin == 'Approved') and (complaint.approvedBythree != 'Approved'):
            complaint.approvedBythree = 'Approved'
            db.session.commit()
            flash('Complaint approved successfully', 'success')
            return redirect(url_for('three'))
        else:
            flash('Complaint not found', 'error')
    elif current_user.role == 'four':
        complaint = Complaint.query.get(complaint_id)
        if (complaint.approvedBythree == 'Approved') and (complaint.approvedByfour != 'Approved'):
            complaint.approvedByfour = 'Approved'
            db.session.commit()
            flash('Complaint approved successfully', 'success')
            return redirect(url_for('four'))
        else:
            flash('Complaint not found', 'error')
    elif current_user.role == 'five':
        complaint = Complaint.query.get(complaint_id)
        if (complaint.approvedByfour == 'Approved') and (complaint.approvedByfive != 'Approved'):
            complaint.approvedByfive = 'Approved'
            db.session.commit()
            flash('Complaint approved successfully', 'success')
            return redirect(url_for('five'))
        else:
            flash('Complaint not found', 'error') 
    elif current_user.role == 'super_admin':
        complaint = Complaint.query.get(complaint_id)
        if (complaint.approvedByfive == 'Approved') and (complaint.approvedBySuperAdmin != 'Approved'):
            complaint.approvedBySuperAdmin = 'Approved'
            db.session.commit()
            flash('Complaint approved successfully', 'success')
            return redirect(url_for('super_admin'))
        else:
            flash('Complaint not found', 'error')    
    else:
        flash('Unauthorized access', 'error')
    


@app.route('/manage_complaint/<int:complaint_id>/decline', methods=['POST'])
@login_required
def decline_complaint(complaint_id):
    if current_user.role == 'admin':
        complaint = Complaint.query.get(complaint_id)
        if complaint:
            complaint.approvedByAdmin = 'Declined'
            db.session.commit()
            flash('Complaint declined successfully', 'success')
            return redirect(url_for('admin'))
        else:
            flash('Complaint not found', 'error')
    
    
    elif current_user.role == 'three':
        complaint = Complaint.query.get(complaint_id)
        if complaint:
            complaint.approvedBythree = 'Declined'
            db.session.commit()
            flash('Complaint declined successfully', 'success')
            return redirect(url_for('three'))
        else:
            flash('Complaint not found', 'error')
        
    elif current_user.role == 'four':
        complaint = Complaint.query.get(complaint_id)
        if complaint:
            complaint.approvedByfour = 'Declined'
            db.session.commit()
            flash('Complaint declined successfully', 'success')
            return redirect(url_for('four'))
        else:
            flash('Complaint not found', 'error')    
    
    elif current_user.role == 'five':
        complaint = Complaint.query.get(complaint_id)
        if complaint:
            complaint.approvedByfive = 'Declined'
            db.session.commit()
            flash('Complaint declined successfully', 'success')
            return redirect(url_for('five'))
        else:
            flash('Complaint not found', 'error')



    else:
        flash('Unauthorized access', 'error')
    
   
   

    

  
    


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_more_super_admin()
    app.run(debug=True)
