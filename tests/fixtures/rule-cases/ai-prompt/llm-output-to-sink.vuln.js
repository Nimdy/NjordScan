// VULNERABLE: AI model output flows into eval / shell / SQL — never trust it.
import OpenAI from 'openai';
import { execSync } from 'child_process';

const openai = new OpenAI();
const db = require('./db');

// (1) eval directly on the model's reply
export async function runMath(req) {
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: req.body.expr }],
  });
  return eval(completion.choices[0].message.content);
}

// (2) model output stored in a named var, then run as a shell command
export async function runTool(req) {
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: req.body.task }],
  });
  const aiCommand = completion.choices[0].message.content;
  return execSync(aiCommand);
}

// (2b) model output spliced into a raw SQL query
export async function runQuery(req) {
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: req.body.ask }],
  });
  const generatedSql = completion.choices[0].message.content;
  return db.query(`${generatedSql}`);
}
