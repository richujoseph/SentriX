const Icon = ({ path, filled = false }) => (
  <svg viewBox="0 0 24 24" width="24" height="24" fill={filled ? "currentColor" : "none"}
    stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    {path}
  </svg>
);

const FEATURES = [
  {
    title: "Suricata IDS ingestion",
    body: "Captured traffic is scored against custom rules — scans, brute force, DNS tunneling, stealth probes — and streamed into the pipeline.",
    icon: <><path d="M12 2 4 6v6c0 5 3.5 8 8 10 4.5-2 8-5 8-10V6l-8-4Z" /></>,
  },
  {
    title: "Source correlation",
    body: "A sliding-window engine groups related alerts by source into a single incident, so one attack is one story — not a hundred rows.",
    icon: <><circle cx="6" cy="6" r="3" /><circle cx="18" cy="18" r="3" /><path d="M9 6h6a3 3 0 0 1 3 3v6" /></>,
  },
  {
    title: "Criticality-weighted scoring",
    body: "Severity blends alert priority, volume and diversity, multiplied by the targeted asset's criticality — a hit on your database outranks a workstation.",
    icon: <><path d="M3 3v18h18" /><path d="M7 15l4-5 3 3 5-7" /></>,
  },
  {
    title: "MITRE ATT&CK timeline",
    body: "Each incident is tagged with the tactics it exhibited, in order, so the timeline reads as Reconnaissance → Credential Access → Exfiltration.",
    icon: <><path d="M4 6h16M4 12h16M4 18h10" /><circle cx="19" cy="18" r="2" /></>,
  },
  {
    title: "AI incident narratives",
    body: "A local or cloud LLM writes a plain-English summary and a recommended action for every high-severity incident — with a safe fallback if it's offline.",
    icon: <><rect x="4" y="4" width="16" height="16" rx="3" /><path d="M9 9h6M9 13h6M9 17h3" /></>,
  },
  {
    title: "Asset inventory & reports",
    body: "An nmap scanner infers host roles and criticality; any incident exports to a formatted PDF report for handoff.",
    icon: <><rect x="3" y="4" width="18" height="5" rx="1.5" /><rect x="3" y="13" width="18" height="5" rx="1.5" /><path d="M7 6.5h.01M7 15.5h.01" /></>,
  },
];

const STEPS = [
  ["Detect", "Suricata turns captured packets into alerts."],
  ["Ingest", "Alerts stream into the API, deduplicated."],
  ["Correlate", "Alerts group by source into scored incidents."],
  ["Summarize", "An LLM writes the narrative and next step."],
  ["Triage", "You review a short, ranked incident list."],
];

const STATS = [
  ["4,816", "packets captured"],
  ["253 : 1", "packets → alerts"],
  ["6.3 : 1", "alerts → incidents"],
  ["3", "incidents to review"],
];

export default function Landing() {
  return (
    <div className="landing">
      <header className="lp-nav">
        <a className="brand" href="#/">
          <span className="brand-mark" aria-hidden="true" />
          SentriX
        </a>
        <nav className="lp-nav-links">
          <a href="#features">Features</a>
          <a href="#how">How it works</a>
          <a className="lp-nav-cta" href="#/dashboard">Open dashboard →</a>
        </nav>
      </header>

      <section className="lp-hero">
        <div className="lp-hero-text">
          <span className="lp-eyebrow">AI-assisted SOC triage</span>
          <h1>
            Turn alert noise into <span className="lp-grad">clear incidents.</span>
          </h1>
          <p className="lp-sub">
            SentriX correlates raw IDS alerts into scored, MITRE-mapped incidents and
            writes a plain-English narrative for each one — so analysts read a short
            list of what matters, not thousands of rows.
          </p>
          <div className="lp-cta-row">
            <a className="lp-btn lp-btn-primary" href="#/dashboard">Open dashboard</a>
            <a className="lp-btn lp-btn-ghost" href="#how">See how it works</a>
          </div>
          <div className="lp-stats">
            {STATS.map(([v, l]) => (
              <div key={l} className="lp-stat">
                <span className="lp-stat-v">{v}</span>
                <span className="lp-stat-l">{l}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="lp-hero-card" aria-hidden="true">
          <div className="lp-card-head">
            <span className="lp-sev-badge">CRITICAL<b>75.6</b></span>
            <span className="lp-card-id">#1 · Open</span>
          </div>
          <div className="lp-card-route">
            <div><span className="lp-k">Source</span><span className="mono">172.30.0.66</span></div>
            <span className="lp-arrow">→</span>
            <div><span className="lp-k">Target</span><span className="mono">sentrix-target-redis-1</span></div>
          </div>
          <div className="lp-chips">
            <span className="lp-chip">TA0043 Reconnaissance</span>
            <span className="lp-chip-arrow">→</span>
            <span className="lp-chip">TA0006 Credential Access</span>
          </div>
          <p className="lp-card-text">
            An internal host attempted reconnaissance via TCP SYN scan, then launched
            SSH brute force against critical internal targets…
          </p>
          <div className="lp-pipe">
            {STEPS.map(([s], i) => (
              <span key={s} className={`lp-pipe-dot ${i < 4 ? "done" : ""}`} />
            ))}
          </div>
        </div>
      </section>

      <section id="features" className="lp-section">
        <div className="lp-section-head">
          <h2>Everything a first-pass triage needs</h2>
          <p>From packet to prioritized incident, in one pipeline.</p>
        </div>
        <div className="lp-features">
          {FEATURES.map((f) => (
            <article key={f.title} className="lp-feature">
              <span className="lp-feature-icon"><Icon path={f.icon} /></span>
              <h3>{f.title}</h3>
              <p>{f.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section id="how" className="lp-section lp-how">
        <div className="lp-section-head">
          <h2>How it works</h2>
          <p>Five stages, fully automated.</p>
        </div>
        <ol className="lp-steps">
          {STEPS.map(([title, body], i) => (
            <li key={title} className="lp-step">
              <span className="lp-step-n">{i + 1}</span>
              <h3>{title}</h3>
              <p>{body}</p>
            </li>
          ))}
        </ol>
      </section>

      <section className="lp-final">
        <h2>Ready to see it in action?</h2>
        <p>Open the live dashboard, or run the bundled attack lab to watch the loop end to end.</p>
        <a className="lp-btn lp-btn-primary" href="#/dashboard">Open dashboard</a>
      </section>

      <footer className="lp-footer">
        <span className="brand"><span className="brand-mark" aria-hidden="true" />SentriX</span>
        <span className="lp-footer-note">AI-assisted network alert triage · demo project</span>
      </footer>
    </div>
  );
}
