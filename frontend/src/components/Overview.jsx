import { useEffect, useState } from "react";
import { fetchOverview } from "../api.js";

const REFRESH_MS = 15000;

function Stat({ label, value, tone, href }) {
  const content = (
    <>
      <span className="stat-value">{value ?? "–"}</span>
      <span className="stat-label">{label}</span>
    </>
  );
  return href ? (
    <a className={`stat stat-${tone}`} href={href}>
      {content}
    </a>
  ) : (
    <div className={`stat stat-${tone}`}>{content}</div>
  );
}

export default function Overview() {
  const [counts, setCounts] = useState(null);

  useEffect(() => {
    const controller = new AbortController();
    const load = () =>
      fetchOverview(controller.signal)
        .then(setCounts)
        .catch(() => {}); // the pages show their own connection errors
    load();
    const timer = setInterval(load, REFRESH_MS);
    return () => {
      controller.abort();
      clearInterval(timer);
    };
  }, []);

  return (
    <section className="overview" aria-label="Overview">
      <Stat label="Total alerts" value={counts?.alerts} tone="neutral" />
      <Stat label="Incidents" value={counts?.incidents} tone="neutral" href="#/dashboard" />
      <Stat
        label="High-severity open"
        value={counts?.highOpen}
        tone={counts?.highOpen ? "alert" : "neutral"}
        href="#/dashboard"
      />
    </section>
  );
}
