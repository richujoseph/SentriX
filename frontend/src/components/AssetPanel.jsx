import { formatDateTime, shortHostname } from "../format.js";

function Row({ label, children }) {
  return (
    <div className="kv-row">
      <dt>{label}</dt>
      <dd>{children ?? <span className="muted">—</span>}</dd>
    </div>
  );
}

function AssetCard({ target, alertCount }) {
  return (
    <div className="asset-card">
      <div className="asset-head">
        <div>
          <div className="asset-name">{target.known_asset ? shortHostname(target.hostname) ?? target.ip : target.ip}</div>
          {target.known_asset && <div className="mono muted">{target.ip}</div>}
        </div>
        {target.known_asset ? (
          <span className={`tag crit-${target.criticality}`}>crit {target.criticality}</span>
        ) : (
          <span className="tag tag-unknown">not in inventory</span>
        )}
      </div>
      {target.known_asset ? (
        <dl className="kv">
          <Row label="Role">{target.role && <span className="capitalize">{target.role.replace("_", " ")}</span>}</Row>
          <Row label="Hostname">{target.hostname && <span className="mono">{target.hostname}</span>}</Row>
          <Row label="MAC">{target.mac && <span className="mono">{target.mac}</span>}</Row>
          <Row label="First seen">{target.first_seen && formatDateTime(target.first_seen)}</Row>
          <Row label="Last seen">{target.last_seen && formatDateTime(target.last_seen)}</Row>
          <Row label="Alerts">{alertCount}</Row>
        </dl>
      ) : (
        <p className="muted asset-unknown">
          This host isn't in the asset inventory, so its role and criticality are unknown. {alertCount} alert
          {alertCount === 1 ? "" : "s"} targeted it.
        </p>
      )}
    </div>
  );
}

export default function AssetPanel({ targets, alerts }) {
  const counts = new Map();
  for (const alert of alerts) counts.set(alert.dest_ip, (counts.get(alert.dest_ip) ?? 0) + 1);

  return (
    <section className="panel">
      <h2 className="panel-title">
        Targeted asset{targets.length === 1 ? "" : "s"}
        {targets.length > 1 && <span className="panel-count">{targets.length}</span>}
      </h2>
      {targets.length === 0 ? (
        <p className="muted">No recorded target.</p>
      ) : (
        <div className="asset-list">
          {targets.map((target) => (
            <AssetCard key={target.ip} target={target} alertCount={counts.get(target.ip) ?? 0} />
          ))}
        </div>
      )}
    </section>
  );
}
