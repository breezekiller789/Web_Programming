from flask import Flask, render_template, request
from flask_socketio import SocketIO, send, emit
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

messages = []
username = None
lst = []

@app.route('/', methods=['GET'])
def homepage():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def user_login():
    global messages
    global username
    global lst
    username = request.form.get('username')
    password = request.form.get('password')
    # lst.append(username+" has connected!!")
    messages.append(username+" has connected!")
    print(messages)
    print("User:{}\tPassword:{}".format(username, password))
    return render_template('index.html', messages = messages)
    # return render_template('index.html')

@socketio.on('message')
def handle_message(message):
    print('received message = '+message)
    # if message == "An user has connected!":
    #     pass
    # else:
    send(message, broadcast=True)

# @socketio.on('new_username', namespace='/private')
# def new_user(msg):
#     global username
#     # print(msg)
#     messages.append(request.sid)
#     print(messages)
#     # emit('new_private_message', "hello~~~~", room = messages[idx])

if __name__ == "__main__":
    socketio.run(app, host="localhost", port=5000, debug=True)
