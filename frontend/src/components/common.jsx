import { VERDICT_COLORS } from '../api/client';

export function Card({ title, note, children, action }) {
  return (
    <section className="card">
      {(title || action) && (
        <header className="page-head" style={{ marginBottom: 12 }}>
          <div>
            {title && <h2>{title}</h2>}
            {note && <p className="subtle" style={{ margin: 0 }}>{note}</p>}
          </div>
          {action}
        </header>
      )}
      {children}
    </section>
  );
}

export function StatTile({ label, value, note, alarm = false }) {
  return (
    <div className="card">
      <div className="tile-label">{label}</div>
      <div className={`tile-value${alarm ? ' alarm' : ''}`}>{value}</div>
      {note && <div className="tile-note">{note}</div>}
    </div>
  );
}

/* The verdict word is always present; the colour only reinforces it. */
export function Verdict({ decision }) {
  return (
    <span className={`badge verdict-${decision}`}>
      <span className="dot" style={{ background: VERDICT_COLORS[decision] }} />
      {decision}
    </span>
  );
}

export function DeviceStatus({ status }) {
  return (
    <span className={`badge device-${status}`}>
      <span className="dot" />
      {status}
    </span>
  );
}

export function ErrorBanner({ error }) {
  if (!error) return null;
  return <div className="error">{error.message || String(error)}</div>;
}

export function Empty({ children = 'Nothing to show yet.' }) {
  return <p className="empty">{children}</p>;
}

export function Legend({ items }) {
  return (
    <div className="legend">
      {items.map((item) => (
        <span className="legend-item" key={item.label}>
          <span className="legend-swatch" style={{ background: item.color }} />
          {item.label}
        </span>
      ))}
    </div>
  );
}

export function Pills({ values, empty = 'any' }) {
  if (!values?.length) return <span className="subtle">{empty}</span>;
  return values.map((value) => <span className="pill" key={value}>{value}</span>);
}
