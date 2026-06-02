import { Client } from 'pg';
export async function runQuery(q: string) {
  const client = new Client();
  return client.query('SELECT * FROM items WHERE name = ' + q);  // sqli — reachable from the route
}
