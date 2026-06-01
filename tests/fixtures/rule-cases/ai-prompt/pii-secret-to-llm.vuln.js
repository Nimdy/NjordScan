// VULNERABLE: secrets / PII sent into the AI prompt.
import OpenAI from 'openai';

const openai = new OpenAI();

// (1) a secret from process.env placed into prompt content
export async function leakSecret() {
  return openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'user', content: `Use this admin key: ${process.env.STRIPE_SECRET_KEY}` },
    ],
  });
}

// (2) the entire request body sent as the prompt
export async function sendAll(req) {
  return openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: JSON.stringify(req.body) }],
  });
}

// (3) obvious PII interpolated into the prompt
export async function summarize(customer) {
  return openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'user', content: `Customer SSN is ${customer.ssn} and card ${customer.creditCard}` },
    ],
  });
}
