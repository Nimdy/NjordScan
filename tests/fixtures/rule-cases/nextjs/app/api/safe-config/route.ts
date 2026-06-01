// SAFE: hand-picks one non-secret value instead of dumping process.env.
export async function GET() {
  return Response.json({ region: process.env.AWS_REGION ?? 'us-east-1' });
}
