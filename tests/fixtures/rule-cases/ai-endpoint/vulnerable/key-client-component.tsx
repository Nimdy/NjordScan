'use client';
// ai.key-clientside + ai.dangerously-allow-browser:
// An OpenAI client built in a client component, with the browser-safety override
// turned on. The API key ships to every visitor's browser.
import { useState } from 'react';
import OpenAI from 'openai';

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  dangerouslyAllowBrowser: true,
});

export default function Chat() {
  const [out, setOut] = useState('');
  async function ask() {
    const r = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      max_tokens: 200,
      messages: [{ role: 'user', content: 'hi' }],
    });
    setOut(r.choices[0].message.content ?? '');
  }
  return <button onClick={ask}>{out || 'Ask'}</button>;
}
