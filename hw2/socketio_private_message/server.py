#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request
from flask_socketio import SocketIO, send, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey'
socketio = SocketIO(app)

users = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/orginate')
def orginate():
    socketio.emit('server orginated', 'Something happened on the server!')
    return '<h1>Sent!</h1>'

@socketio.on('message from user', namespace='/messages')
def receive_message_from_user(message):
    print('USER MESSAGE: {}'.format(message))
    emit('from flask', message.upper(), broadcast=True)

@socketio.on('username', namespace='/private')
def receive_username(username):
    global users
    print(type(request.sid))
    # users[username] = request.sid
    users.append({username : request.sid})
    print(users)
    print('Username added!')

@socketio.on('private_message', namespace='/private')
def private_message(payload):
    name = payload['username']
    recipient_session_id = users[0]
    message = payload['message']

    emit('new_private_message', message, room=recipient_session_id)

# @socketio.on('message')
# def receive_message(message):
#     print('########: {}'.format(message))
#     send('This is a message from Flask.')

# @socketio.on('custom event')
# def receive_custom_event(message):
#     print('THE CUSTOM MESSAGE IS: {}'.format(message['name']))
#     emit('from flask', {'extension' : 'Flask-SocketIO'}, json=True)


if __name__ == '__main__':
    socketio.run(app, host='localhost', port=5000)
    # app.run(host="localhost", port = 5000)
