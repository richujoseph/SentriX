// Turn an incident's alerts into a readable timeline: consecutive identical
// alerts collapse into one row, and rows are grouped into phases whenever the
// MITRE tactic changes.

export const UNMAPPED = { id: null, name: "Unmapped activity" };

export function buildTimeline(alerts, tactics) {
  const tacticByAlert = new Map();
  for (const tactic of tactics) {
    for (const alertId of tactic.alert_ids) tacticByAlert.set(alertId, tactic);
  }

  const rows = [];
  for (const alert of alerts) {
    const tactic = tacticByAlert.get(alert.id) ?? UNMAPPED;
    const last = rows.at(-1);
    if (last && last.signature === alert.signature && last.dest_ip === alert.dest_ip && last.tactic === tactic) {
      last.count += 1;
      last.end = alert.timestamp;
      if (alert.dest_port != null) last.ports.add(alert.dest_port);
      last.severity = Math.min(last.severity ?? 9, alert.severity ?? 9);
      continue;
    }
    rows.push({
      key: alert.id,
      tactic,
      signature: alert.signature,
      category: alert.category,
      dest_ip: alert.dest_ip,
      ports: new Set(alert.dest_port != null ? [alert.dest_port] : []),
      severity: alert.severity,
      start: alert.timestamp,
      end: alert.timestamp,
      count: 1,
    });
  }

  const phases = [];
  for (const row of rows) {
    const last = phases.at(-1);
    if (last && last.tactic === row.tactic) last.rows.push(row);
    else phases.push({ key: row.key, tactic: row.tactic, start: row.start, rows: [row] });
  }
  return phases;
}
