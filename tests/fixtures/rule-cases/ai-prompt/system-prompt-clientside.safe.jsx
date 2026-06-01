'use client';
// SAFE: the client only sends the user's message to our own server; no prompt here.
import { useState } from 'react';

export function Chat() {
  const [out, setOut] = useState('');

  async function send(message) {
    const res = await fetch('/api/chat', {
      method: 'POST',
      body: JSON.stringify({ message }),
    });
    const data = await res.json();
    setOut(data.reply);
  }

  return <button onClick={() => send('hi')}>{out}</button>;
}
