import { Client } from 'pg';
import _ from 'lodash';

// Builds a query by string concatenation — SQL injection.
export async function searchProducts(term: string) {
  const client = new Client();
  return client.query('SELECT * FROM products WHERE name LIKE %' + term + '%');
}

// Renders a server-side template from user input — lodash.template is CVE-2021-23337
// (command injection). Because we actually CALL template(), NjordScan marks the CVE EXPLOITABLE.
export function renderLabel(tpl: string, data: object) {
  return _.template(tpl)(data);
}
