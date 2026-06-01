import { Client } from 'pg';
export async function deadCode(q: string) {
  const client = new Client();
  return client.query('SELECT * FROM users WHERE id = ' + q);  // sqli — but unreachable dead code
}
