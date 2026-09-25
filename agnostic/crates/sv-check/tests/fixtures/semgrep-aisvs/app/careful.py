"""The same calls written the careful way: the rules above find nothing here."""
import os

from flask import Flask, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])


@app.post("/ask")
def ask():
    question = request.form["question"]
    moderation = client.moderations.create(input=question)
    if moderation.results[0].flagged:
        return "That question cannot be answered here."
    reply = client.chat.completions.create(
        model="gpt-5",
        max_tokens=400,
        messages=[
            {"role": "system", "content": "You are a help-desk assistant."},
            {"role": "user", "content": question},
        ],
    )
    return reply.choices[0].message.content
