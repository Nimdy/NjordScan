// SAFE: model output chooses a label; we map it to a real action via allowlist.
import OpenAI from 'openai';

const openai = new OpenAI();

export async function runTool(req) {
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: req.body.task }],
  });
  const intent = completion.choices[0].message.content?.trim();

  // never executed — looked up in a fixed map we wrote
  const handlers = { refund: doRefund, status: doStatus };
  return handlers[intent]?.();
}

function doRefund() { return 'refunded'; }
function doStatus() { return 'ok'; }
