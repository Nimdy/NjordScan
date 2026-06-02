import { paletteFor } from 'analytics-color-utils';
import { format } from 'date-fns';
import { get } from 'lodash';

const sampleData = [
  { label: 'Signups', value: 1280 },
  { label: 'Active', value: 940 },
  { label: 'Churned', value: 64 },
];

export default function DashboardPage() {
  const colors = paletteFor('cb_safe');
  const today = format(new Date(), 'yyyy-MM-dd');

  return (
    <main style={{ fontFamily: 'system-ui', padding: 24 }}>
      <h1>Acme Dashboard</h1>
      <p>Report generated {today}</p>
      <ul>
        {sampleData.map((row, i) => (
          <li key={row.label} style={{ color: get(colors, i, '#000') }}>
            {row.label}: {row.value}
          </li>
        ))}
      </ul>
    </main>
  );
}
