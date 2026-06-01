// SAFE: AI model output rendered as text (React escapes it).
import { useState } from 'react';
import OpenAI from 'openai';

export function Answer() {
  const [aiReply, setAiReply] = useState('');

  async function ask(question) {
    const openai = new OpenAI({ dangerouslyAllowBrowser: true });
    const res = await openai.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: question }],
    });
    setAiReply(res.choices[0].message.content ?? '');
  }

  // rendered as text — React escapes it, no XSS
  return <p className="whitespace-pre-wrap" onClick={() => ask('hi')}>{aiReply}</p>;
}
