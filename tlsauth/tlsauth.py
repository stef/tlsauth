#!/usr/bin/env python

# run with
# env/bin/uwsgi --socket 127.0.0.1:8080 --chdir $basedir/tlsauth -pp $basedir -w tlsauth_wsgi -p 1 --virtualenv $basedir/env

from flask import Flask, render_template, request, abort, redirect, Response
app = Flask(__name__)

@app.route('/')
def about():
    return Response(request.environ['verified'] + "<br />" + request.environ['dn']) #render_template('about.html')
