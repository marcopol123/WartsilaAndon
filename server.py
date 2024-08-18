from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from datetime import datetime, timedelta
import psycopg2
from psycopg2 import sql

# Flask app setup
app = Flask(__name__)
app.secret_key = 'pera'
app.config['JWT_SECRET_KEY'] = 'banana'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=10)

# Database credentials
db_username = 'postgres'
db_password = 'password'
db_name = 'support_db'
db_host = 'localhost'
db_port = '5432'


# Create the database if it doesn't exist
def create_database():
    conn = psycopg2.connect(dbname='postgres', user=db_username, password=db_password, host=db_host, port=db_port)
    conn.autocommit = True
    cursor = conn.cursor()
    cursor.execute(sql.SQL('SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s'), [db_name])
    exists = cursor.fetchone()
    if not exists:
        cursor.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(db_name)))
    cursor.close()
    conn.close()


create_database()

# Configure the PostgreSQL database connection. Default port is 5432.
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_username}:{db_password}@localhost/{db_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
jwt = JWTManager(app)


# Database table models
class SupportRequests(db.Model):
    __tablename__ = 'SupportRequests'
    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Station = db.Column(db.Integer, db.ForeignKey('Stations.ID'), nullable=False)
    Operator = db.Column(db.Text, db.ForeignKey('Operators.Username'), nullable=False)
    Office = db.Column(db.Text, db.ForeignKey('Offices.Name'), nullable=False)
    OperatorMsg = db.Column(db.Text)
    SupportMsg = db.Column(db.Text)
    SubmTime = db.Column(db.DateTime, nullable=False)
    HandlTime = db.Column(db.DateTime)
    ComplTime = db.Column(db.DateTime)
    # Relationships
    operator = db.relationship('Operators', backref=db.backref('support_requests', lazy=True))
    station = db.relationship('Stations', backref=db.backref('support_requests', lazy=True))
    office = db.relationship('Offices', backref=db.backref('support_requests', lazy=True))


class Operators(db.Model):
    __tablename__ = 'Operators'
    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Username = db.Column(db.Text, nullable=False, unique=True)
    Password = db.Column(db.Text, nullable=False)
    Station = db.Column(db.Integer, db.ForeignKey('Stations.ID'), nullable=False)
    # Relationships
    station = db.relationship('Stations', backref=db.backref('operators', lazy=True))


class SupportTeam(db.Model):
    __tablename__ = 'SupportTeam'
    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Username = db.Column(db.Text, nullable=False, unique=True)
    Password = db.Column(db.Text, nullable=False)
    Office = db.Column(db.Text, db.ForeignKey('Offices.Name'), nullable=False)
    # Relationships
    station = db.relationship('Offices', backref=db.backref('support_team', lazy=True))


class Administrators(db.Model):
    __tablename__ = 'Administrators'
    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Username = db.Column(db.Text, nullable=False)
    Password = db.Column(db.Text, nullable=False)


class Stations(db.Model):
    __tablename__ = 'Stations'
    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Status = db.Column(db.Text, nullable=False)
    InactiveTime = db.Column(db.Interval, default=timedelta(0))


class Offices(db.Model):
    __tablename__ = 'Offices'
    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Name = db.Column(db.Text, nullable=False, unique=True)


# Create database tables if they don't exist
with app.app_context():
    db.create_all()


# Fill the database only if tables are empty
with app.app_context():
    if not Offices.query.all():
        db.session.add(Offices(Name='Tools'))
        db.session.add(Offices(Name='Quality'))
        db.session.add(Offices(Name='Product'))
        db.session.add(Offices(Name='Logistics'))
        db.session.commit()
    if not Stations.query.all():
        db.session.add(Stations(Status='Operational', InactiveTime=None))
        db.session.add(Stations(Status='Operational', InactiveTime=None))
        db.session.add(Stations(Status='Operational', InactiveTime=None))
        db.session.commit()
    if not Administrators.query.all():
        db.session.add(Administrators(Username='admin', Password='password'))
        db.session.commit()
    if not Operators.query.all():
        db.session.add(Operators(Username='operator1', Password='password', Station=1))
        db.session.add(Operators(Username='operator2', Password='password', Station=2))
        db.session.add(Operators(Username='operator3', Password='password', Station=3))
        db.session.commit()
    if not SupportTeam.query.all():
        db.session.add(SupportTeam(Username='support1', Password='password', Office='Tools'))
        db.session.add(SupportTeam(Username='support2', Password='password', Office='Quality'))
        db.session.add(SupportTeam(Username='support3', Password='password', Office='Product'))
        db.session.add(SupportTeam(Username='support4', Password='password', Office='Logistics'))
        db.session.commit()


class Station:
    def __init__(self, number, status):
        self.number = number
        self.status = status
        self.inactive_since = None

    def set_inactive(self):
        self.status = 'Issue raised'
        self.inactive_since = datetime.now().replace(microsecond=0)

    def get_inactive_duration(self):
        if self.status == 'Operational' or not self.inactive_since:
            return timedelta(0)
        return datetime.now().replace(microsecond=0) - self.inactive_since


# Initialize stations objects
with app.app_context():
    station1 = Station(1, Stations.query.filter_by(ID=1).first().Status)
    station2 = Station(2, Stations.query.filter_by(ID=2).first().Status)
    station3 = Station(3, Stations.query.filter_by(ID=3).first().Status)

stations_array = [station1, station2, station3]


@app.route('/')
def index():
    return redirect(url_for('login_page'))


# Login page
@app.route('/login_page')
def login_page():
    return render_template('login.html')


# Token creation
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    # Database lookup
    operator = Operators.query.filter_by(Username=username, Password=password).first()
    support = SupportTeam.query.filter_by(Username=username, Password=password).first()
    admin = Administrators.query.filter_by(Username=username, Password=password).first()

    if operator:
        access_token = create_access_token(identity=username, additional_claims={'role': 'operator'})
        return jsonify(access_token=access_token, redirect_url=url_for('create_request'))
    elif support:
        access_token = create_access_token(identity=username, additional_claims={'role': 'support'})
        return jsonify(access_token=access_token, redirect_url=url_for('support'))
    elif admin:
        access_token = create_access_token(identity=username, additional_claims={'role': 'admin'})
        return jsonify(access_token=access_token, redirect_url=url_for('admin'))
    else:
        return jsonify({"msg": "Invalid username or password"}), 401


# Logout
@app.route('/logout', methods=['POST'])
def logout():
    response = jsonify({"msg": "Logout successful", 'redirect_url': url_for('login_page')})
    return response


# Request form
@app.route('/create_request', methods=['GET', 'POST'])
@jwt_required()
def create_request():
    current_user = get_jwt_identity()
    claims = get_jwt()
    if claims['role'] == 'operator':
        return render_template('create_request.html', logged_in_user=current_user)
    else:
        return jsonify({"msg": "Unauthorized"}), 403


# Submit request
@app.route('/submit_request', methods=['POST'])
@jwt_required()
def submit_request():
    current_user = get_jwt_identity()

    operator = Operators.query.filter_by(Username=current_user).first()
    station = operator.Station

    if station == 1:
        station1.set_inactive()
    elif station == 2:
        station2.set_inactive()
    elif station == 3:
        station3.set_inactive()

    data = request.get_json()
    office = data.get('recipient')
    operator_msg = data.get('operatorMsg')
    submitted = datetime.now().replace(microsecond=0)

    new_request = SupportRequests(
        Office=office,
        Station=station,
        Operator=current_user,
        OperatorMsg=operator_msg,
        SubmTime=submitted
    )
    db.session.add(new_request)
    db.session.commit()

    return jsonify({'message': 'Request submitted successfully'})


# Support page
@app.route('/support', methods=['GET', 'POST'])
@jwt_required()
def support():
    current_user = get_jwt_identity()
    claims = get_jwt()
    if claims['role'] == 'support':
        support_user = SupportTeam.query.filter_by(Username=current_user).first()
        requests = SupportRequests.query.filter_by(Office=support_user.Office).all()
        return render_template('support.html', requests=requests, office=support_user.Office)
    else:
        return jsonify({"msg": "Unauthorized"}), 403


@app.route('/update_request', methods=['POST'])
@jwt_required()
def update_request():
    claims = get_jwt()
    if claims['role'] == 'support':
        data = request.get_json()
        request_id = data.get('requestId')
        support_msg = data.get('supportMsg')
        support_request = SupportRequests.query.filter_by(ID=request_id).first()
        station_number = support_request.Station

        if not support_request:
            return jsonify({"msg": "Request not found"}), 404

        support_request.SupportMsg = support_msg
        if data.get('takenInCharge') and not support_request.HandlTime:
            support_request.HandlTime = datetime.now().replace(microsecond=0)
            for s in stations_array:
                if s.number == station_number:
                    s.status = 'Processing request'
                    break

        if data.get('resolved') and not support_request.ComplTime:
            support_request.ComplTime = datetime.now().replace(microsecond=0)
            for s in stations_array:
                if s.number == station_number:
                    # Update Stations table
                    Stations.query.filter_by(ID=station_number).first().Status = 'Operational'
                    Stations.query.filter_by(ID=station_number).first().InactiveTime += s.get_inactive_duration()
                    # Update station object
                    s.status = 'Operational'
                    s.inactive_since = None
                    break

        db.session.commit()

        return jsonify({"msg": "Request updated successfully"})
    else:
        return jsonify({"msg": "Unauthorized"}), 403


@app.route('/admin', methods=['GET', 'POST'])
@jwt_required()
def admin():
    # current_user = get_jwt_identity()
    claims = get_jwt()
    if claims['role'] == 'admin':
        requests = SupportRequests.query.all()
        stations = Stations.query.all()
        return render_template('admin.html', requests=requests, stations=stations)
    else:
        return jsonify({"msg": "Unauthorized"}), 403


@app.route('/delete_request', methods=['POST'])
@jwt_required()
def delete_request():
    data = request.get_json()
    request_id = data.get('requestId')

    if not request_id:
        return jsonify({"msg": "Request ID is required"}), 400

    try:
        support_request = SupportRequests.query.filter_by(ID=request_id).first()
        db.session.delete(support_request)
        db.session.commit()
        return jsonify({"msg": "Request deleted successfully"})
    except Exception as e:
        return jsonify({"msg": f"Error deleting request: {e}"}), 500


# Serve station status
@app.route('/status', methods=['GET'])
def get_status():
    return jsonify({
        'station1': {
            'status': station1.status,
            'inactive_duration': str(station1.get_inactive_duration())
        },
        'station2': {
            'status': station2.status,
            'inactive_duration': str(station2.get_inactive_duration())
        },
        'station3': {
            'status': station3.status,
            'inactive_duration': str(station3.get_inactive_duration())
        }
    })


# Serve monitor.html
@app.route('/monitor')
def monitor():
    return render_template('monitor.html')


if __name__ == '__main__':
    app.run()
