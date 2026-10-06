/* Charts.
 *
 * Allowed and denied are *states*, not arbitrary series, so they use the
 * reserved status palette (good / critical) and always carry their labels.
 * Count charts use a single categorical hue: bar length already encodes the
 * magnitude, so colour is not asked to repeat it.
 */
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { formatNumber, formatTime } from '../api/client';
import { Legend } from './common';

const AXIS = { stroke: 'var(--axis)', tick: { fill: 'var(--text-muted)', fontSize: 11 } };

const TOOLTIP = {
  contentStyle: {
    background: 'var(--surface-1)',
    border: '1px solid var(--border)',
    borderRadius: 8,
    fontSize: 12,
    color: 'var(--text-primary)',
  },
  labelStyle: { color: 'var(--text-secondary)' },
  cursor: { stroke: 'var(--axis)', strokeWidth: 1 },
};

export function DecisionTimeline({ points }) {
  if (!points?.length) return <p className="empty">No requests in this window.</p>;
  const data = points.map((point) => ({
    time: formatTime(point.bucket),
    Allowed: point.allowed,
    Denied: point.denied,
  }));

  return (
    <>
      <ResponsiveContainer width="100%" height={240}>
        <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
          <CartesianGrid stroke="var(--grid)" vertical={false} />
          <XAxis dataKey="time" {...AXIS} minTickGap={36} />
          <YAxis {...AXIS} width={44} allowDecimals={false} />
          <Tooltip {...TOOLTIP} />
          <Area type="monotone" dataKey="Allowed" stackId="d" stroke="var(--status-good)"
                fill="var(--status-good)" fillOpacity={0.7} strokeWidth={2}
                activeDot={{ r: 4, stroke: 'var(--surface-1)', strokeWidth: 2 }} />
          <Area type="monotone" dataKey="Denied" stackId="d" stroke="var(--status-critical)"
                fill="var(--status-critical)" fillOpacity={0.75} strokeWidth={2}
                activeDot={{ r: 4, stroke: 'var(--surface-1)', strokeWidth: 2 }} />
        </AreaChart>
      </ResponsiveContainer>
      <Legend
        items={[
          { label: 'Allowed', color: 'var(--status-good)' },
          { label: 'Denied', color: 'var(--status-critical)' },
        ]}
      />
    </>
  );
}

export function CountBars({ rows, label = 'Requests', color = 'var(--series-1)', width = 170 }) {
  if (!rows?.length) return <p className="empty">Nothing recorded yet.</p>;
  return (
    <>
      <ResponsiveContainer width="100%" height={34 * rows.length + 34}>
        <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 20, bottom: 4, left: 4 }}>
          <CartesianGrid stroke="var(--grid)" horizontal={false} />
          <XAxis type="number" {...AXIS} allowDecimals={false} tickFormatter={formatNumber} />
          <YAxis type="category" dataKey="name" {...AXIS} width={width} />
          <Tooltip {...TOOLTIP} cursor={{ fill: 'var(--plane)' }}
                   formatter={(value) => [formatNumber(value), label]} />
          <Bar dataKey="count" fill={color} radius={[0, 4, 4, 0]} barSize={16} />
        </BarChart>
      </ResponsiveContainer>
      {/* Table view alongside the bars: the counts must be readable exactly. */}
      <div className="table-wrap">
        <table>
          <thead><tr><th>{label}</th><th className="num">Count</th></tr></thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.name}>
                <td>{row.name}</td>
                <td className="num">{formatNumber(row.count)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
