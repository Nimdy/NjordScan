'use strict';

// Minimal OpenAI-compatible stub so the lab app boots with zero dependencies.
// It mirrors the surface of the real `openai` SDK (client.chat.completions.create)
// but instead of calling the API it echoes the user's question back. This keeps
// the AI route fully exercisable offline while preserving the real call shape.

class OpenAIish {
  constructor(opts) {
    this.apiKey = (opts && opts.apiKey) || '';
    this.chat = {
      completions: {
        create: async (params) => {
          const userMsg =
            (params.messages || [])
              .slice()
              .reverse()
              .find((m) => m.role === 'user') || { content: '' };
          // Echo the question as the "model" reply.
          const content = `You said: ${userMsg.content}`;
          return {
            id: 'chatcmpl-stub',
            model: params.model,
            choices: [{ index: 0, message: { role: 'assistant', content } }],
          };
        },
      },
    };
  }
}

module.exports = { OpenAIish };
