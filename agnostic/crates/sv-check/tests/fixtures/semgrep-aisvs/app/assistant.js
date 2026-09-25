// The help-desk assistant again, in JavaScript, with the faults the JavaScript rules look for.
import Anthropic from "@anthropic-ai/sdk";
import { CohereClientV2 } from "cohere-ai";
import express from "express";
import OpenAI from "openai";

const app = express();
const openai = new OpenAI();
const anthropic = new Anthropic();
const cohere = new CohereClientV2();

app.post("/ask", async (req, res) => {
  const reply = await openai.chat.completions.create({
    model: "gpt-5",
    max_tokens: 400,
    messages: [
      { role: "system", content: req.body.persona },
      { role: "user", content: "What are your opening hours?" },
    ],
  });
  res.send(reply.choices[0].message.content);
});

app.post("/summary", async (req, res) => {
  const reply = await anthropic.messages.create({
    model: "claude-sonnet-5",
    system: req.body.instructions,
    messages: [{ role: "user", content: "Summarize the ticket." }],
  });
  res.send(reply.content[0].text);
});

app.post("/triage", async (req, res) => {
  const reply = await cohere.chat({
    model: "command-a",
    safetyMode: "OFF",
    messages: [{ role: "user", content: "Sort this ticket." }],
  });
  res.send(reply.message.content[0].text);
});
