'use client';
// SAFE: a client component that calls OUR OWN /api/chat endpoint over fetch.
// No provider SDK, no API key, no dangerouslyAllowBrowser in the browser.
import { useState } from 'react';

export default function Chat() {
  const [out, setOut] = useState('');
  async function ask() {
    const res = await fetch('/api/chat', {
      method: 'POST',
      body: JSON.stringify({ messages: [{ role: 'user', content: 'hi' }] }),
    });
    const data = await res.json();
    setOut(data.reply ?? '');
  }
  return <button onClick={ask}>{out || 'Ask'}</button>;
}
