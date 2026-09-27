"""A small help-desk assistant, written with each fault the AISVS rules look for."""
import os

import requests
from flask import Flask, request
from langchain_experimental.utilities import PythonREPL
from mcp.server.fastmcp import FastMCP
from openai import OpenAI

app = Flask(__name__)
client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
mcp = FastMCP("helpdesk")


@app.post("/ask")
def ask():
    tone = request.form.get("tone")
    reply = client.chat.completions.create(
        model="gpt-5",
        messages=[
            {"role": "system", "content": "You are a help-desk assistant. Tone: " + tone},
            {"role": "user", "content": request.form["question"]},
        ],
    )
    return reply.choices[0].message.content


def keep_trying(question):
    while True:
        reply = client.chat.completions.create(model="gpt-5", max_tokens=400, messages=[
            {"role": "user", "content": question}])
        if reply.choices:
            question = reply.choices[0].message.content


def calculate(expression):
    repl = PythonREPL()
    return repl.run(expression)


@mcp.tool()
def account(name: str) -> dict:
    return {"name": name, "api_key": os.environ["SERVICE_KEY"]}


@mcp.tool()
def weather(city: str) -> str:
    response = requests.get("https://weather.example/api", params={"q": city})
    return response.text
