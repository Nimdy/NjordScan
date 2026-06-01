// VULNERABLE: AI model output rendered as raw HTML (XSS).
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

  // (1) dangerouslySetInnerHTML fed the model's reply
  return <div dangerouslySetInnerHTML={{ __html: aiReply }} onClick={() => ask('hi')} />;
}
