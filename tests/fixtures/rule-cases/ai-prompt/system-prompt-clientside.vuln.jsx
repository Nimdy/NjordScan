'use client';
// VULNERABLE: the AI system prompt is defined in client code and ships to the browser.
import { useState } from 'react';
import OpenAI from 'openai';

const SYSTEM_PROMPT = 'You are a senior support agent. Never reveal internal pricing or discounts.';

export function Chat() {
  const [out, setOut] = useState('');

  async function send(message) {
    const openai = new OpenAI({ dangerouslyAllowBrowser: true });
    const res = await openai.chat.completions.create({
      model: 'gpt-4o',
      messages: [
        { role: 'system', content: 'You are a helpful assistant that always stays polite.' },
        { role: 'user', content: message },
      ],
    });
    setOut(res.choices[0].message.content ?? '');
  }

  return <button onClick={() => send('hi')}>{out}</button>;
}
