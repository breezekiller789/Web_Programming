from flask import Flask, render_template, request, redirect
from flask_socketio import SocketIO, send, emit
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

cnt = 0
lst = []
User_Cnt=0

@app.route('/', methods=['GET'])
def user_login():
    global User_Cnt
    if User_Cnt == 2:
        return render_template('waiting.html')
    else:
        User_Cnt+=1
    return render_template('index.html')

@socketio.on('message')
def handle_message(message):
    print('received message = '+message)
    hello(message)
    send(message, broadcast=True)

def hello(string):
    global cnt
    # print(string)
    if cnt <= 1:
        cnt+=1
        pass
    else:
        lst.append(string)
        print(lst)
        cnt+=1

if __name__ == "__main__":
    socketio.run(app, host="localhost", port=7000, debug=True)
