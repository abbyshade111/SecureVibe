import xml.etree.ElementTree as ET
from flask import Flask, request

app = Flask(__name__)

@app.post("/import")
def import_feed():
    # Parses attacker-supplied XML with the standard library. No dependency declares this.
    tree = ET.fromstring(request.data)
    return {"tag": tree.tag}
