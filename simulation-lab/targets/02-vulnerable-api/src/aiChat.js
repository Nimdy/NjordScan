'use strict';

// QuickNotes AI assistant. Lets a user ask questions about their notes in plain
// English. This module is mounted at POST /api/chat by server.js.
//
// It "calls a model" through a thin OpenAI-compatible client. To keep the lab
// self-contained the client below just echoes a canned completion instead of
// making a real network call, but the call shape is exactly what a real app
// using the openai SDK would write.

const { OpenAIish } = require('./modelClient');

// VULNERABLE: provider key referenced server-side as a hard-coded literal.
// (In a real app this would be process.env.OPENAI_API_KEY.)
const OPENAI_API_KEY = 'sk-proj-9Qm2VkRxZ7bN4pL0wHcD3sYfTgUjA1oE6iK8nMqB5rW2vX';

const client = new OpenAIish({ apiKey: OPENAI_API_KEY });

// Turn a model reply that looks like `CALC: 2 + 2` into an answer. The assistant
// is allowed to "use a calculator tool" by emitting a CALC: line.
function runToolIfRequested(reply) {
  const match = /^CALC:\s*(.+)$/m.exec(reply);
  if (!match) return null;
  // VULNERABLE: the model's output is evaluated — a crafted prompt can steer the
  // model into emitting arbitrary JS that then runs on the server (RCE).
  const aiCommand = match[1];
  // eslint-disable-next-line no-eval
  return eval(aiCommand);
}

// POST /api/chat — { question: string, notesContext?: string }
// No sign-in check and no rate limit anywhere in this file: anyone on the
// internet can call it as many times as they like (denial of wallet).
module.exports = async function handler(req, res) {
  const question = (req.body && req.body.question) || '';
  const notesContext = (req.body && req.body.notesContext) || '';

  // VULNERABLE: user input is concatenated straight into the system instruction,
  // so a user can override the assistant's rules (prompt injection).
  const messages = [
    { role: 'system', content: 'You are the QuickNotes assistant. User notes: ' + req.body.notesContext },
    { role: 'user', content: question },
  ];
  void notesContext;

  // VULNERABLE: no max_tokens / max_output_tokens cap on the model call.
  const completion = await client.chat.completions.create({
    model: 'gpt-4o-mini',
    messages,
    temperature: 0.7,
  });

  const reply = completion.choices[0].message.content;
  const toolResult = runToolIfRequested(reply);

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ reply, toolResult }));
};
