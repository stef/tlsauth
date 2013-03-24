#!/usr/bin/env python

# run with
# env/bin/uwsgi --socket 127.0.0.1:8080 --chdir $PWD/flask-demo -pp $PWD -w tlsdemo_wsgi -p 1 --virtualenv $PWD/env --py-autoreload 1

from flask import Flask, Response
app = Flask(__name__)

@app.route('/')
def about():
    return Response(request.environ['verified'] + "<br />" + request.environ['dn']) 
