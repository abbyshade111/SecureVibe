# A small Flask app with one of each fault in it, for semgrep to find. Not for running.
import hashlib
import os
import pickle
import subprocess

import requests
import yaml
from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/run")
def run():
    return eval(request.args["expr"])


@app.route("/find")
def find(cursor):
    name = request.args["name"]
    cursor.execute("select * from notes where name = '%s'" % name)


@app.route("/ping")
def ping():
    subprocess.call("ping -c 1 " + request.args["host"], shell=True)


@app.route("/load")
def load():
    return pickle.loads(request.data)


@app.route("/config")
def config():
    return yaml.load(request.data)


@app.route("/go")
def go():
    return redirect(request.args["next"])


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"]).text


@app.route("/insecure")
def insecure():
    return requests.get("https://example.com", verify=False).text


def digest(data):
    return hashlib.md5(data).hexdigest()


def read(name):
    return open(os.path.join("/srv/files", request.args["name"])).read()
