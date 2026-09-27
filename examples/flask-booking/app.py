"""A clinic booking app, of the kind an AI coding tool produces after a few rounds of discussion."""

import xml.etree.ElementTree as ET

import stripe
from authlib.integrations.flask_client import OAuth
from flask import Flask, request

app = Flask(__name__)
oauth = OAuth(app)


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/appointments/import")
def import_appointments():
    # The clinic's old system exports XML. Parsed with the standard library, so nothing in
    # requirements.txt says this app touches XML at all.
    tree = ET.fromstring(request.data)
    return {"imported": len(tree)}


@app.post("/appointments/<int:appointment_id>/pay")
def pay(appointment_id: int):
    # Added late, after the manifest was written. securevibe.toml still says payments = false.
    session = stripe.checkout.Session.create(
        mode="payment",
        line_items=[{"price": "price_consultation", "quantity": 1}],
        success_url="https://clinic.example/done",
    )
    return {"url": session.url}
