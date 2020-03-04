
from flask import Flask, render_template, request, make_response, jsonify, session
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from flask_restful import reqparse, abort, Api, Resource
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, and_
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import uuid
from functools import wraps


app = Flask(__name__)
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////app/login.db'
app.config['SQLALCHEMY_DATABASE_URI'] = r'sqlite:///C:\skola\4\TAMZ\PROJECT\login.db'
app.config['SECRET_KEY'] = 'secret'
login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)
CORS(app)
api = Api(app)  
socketio = SocketIO(app)
curr_user_id = -1

#--------------------------DB------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True)
    password = db.Column(db.String(80))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.Integer)
    recipient = db.Column(db.Integer)
    message = db.Column(db.Text)

    @property
    def serialize(self):
       """Return object data in easily serializable format"""
       return {
        'id': self.id,
        'sender': self.sender,
        'recipient' : self.recipient,
        'message':self.message
       }
#-------------------------API----------------------------------

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token=None
        if 'x-access-token' in request.headers:
            token=request.headers['x-access-token']
        if not token:
            return jsonify({'message':'token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(id=data['id']).first()
        except:
            return jsonify({'message':'token is invalid'}), 401
        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/')
def index():
    return jsonify({'message':'online'})
@app.route('/messages', methods=['POST'])    
@token_required
def get_chat_messages(current_user):
    data = request.get_json()
    messages = Message.query.filter(
        or_(
            and_(
                Message.sender==data['sender'], Message.recipient==data['recipient']
            ), 
            and_(
                Message.sender==data['recipient'], Message.recipient==data['sender']
            )
        )
    ) 
    return jsonify(json_list = [i.serialize for i in messages.all()])
    
@app.route('/user', methods=['GET'])
@token_required
def get_user_list(current_user):
    print(current_user.username)
    users = User.query.filter(User.id != current_user.id)

    output = []

    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['username'] = user.username
        user_data['password'] = user.password
        output.append(user_data)
    return jsonify({'users':output})

@app.route('/user/<int:id>', methods=['GET'])
@token_required
def get_user(current_user, id):
    user = User.query.filter_by(id = id).first()
    if not user:
        return jsonify({'message':'user_not_found'})
    user_data = {}
    user_data['username'] = user.username
    user_data['password'] = user.password

    return jsonify({'user':user_data})

@app.route('/user/<int:id>', methods=['DELETE'])
@token_required
def delete_user(current_user, id):
    user = User.query.filter_by(id = id).first()

    if not user:
        return jsonify({'message':'user not found'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message':'user has been removed'})


@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    print(data)

    hashed_pwd = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], password=hashed_pwd)
    db.session.add(new_user)    
    db.session.commit()

    return jsonify({'message':'new user created!'})

@app.route('/login')
def login():
    print(request.authorization)
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login Requied!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login Requied!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'id':user.id, 'exp':datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token':token.decode('UTF-8'), 'user_id':user.id})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login Requied!"'})


#--------------------------SOCKET--------------------------------

users = {}

@socketio.on('chat message')
def handle_message(payload):
    if int(payload['recipient_id']) in users:
        recipient_session_id = users[int(payload['recipient_id'])]
    else:
        recipient_session_id = 0

    message = payload['message']
    recipient_id = int(payload['recipient_id'])
    sender_id = int(payload['sender'])
    sender_session_id = users[int(payload['sender'])]
    emit('chat message', {'message':message, 'sender':sender_id}, room=recipient_session_id)
    emit('chat message', {'message':message, 'sender':sender_id}, room=sender_session_id)
    msg = Message(sender = sender_id, recipient = recipient_id, message=message)
    db.session.add(msg)    
    db.session.commit()



@socketio.on('chat connect')
def handle_chat_connection(user_id):
    print('********************CONNECTED - '+ str(user_id) +' ************************')
    users[user_id] = request.sid
    print(users)


@socketio.on('chat disconnect')
def handle_chat_disconnect(user_id):
    print('********************DISCONNECTED - '+ str(user_id) +' ************************')
    if(user_id in users):
        del users[user_id]
    print(users)


if __name__ == '__main__':
	socketio.run(app)
