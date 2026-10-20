const dateTime = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});

const timeWithSeconds = new Intl.DateTimeFormat(undefined, {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});

export function formatTime(iso) {
  return timeWithSeconds.format(new Date(iso));
}

export function formatDateTime(iso) {
  return dateTime.format(new Date(iso));
}

export function formatDuration(startIso, endIso) {
  const seconds = Math.max(0, (new Date(endIso ?? startIso) - new Date(startIso)) / 1000);
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

// "sentrix-target-ssh-1.sentrix_lab" -> "sentrix-target-ssh-1"
export function shortHostname(hostname) {
  return hostname?.split(".")[0] ?? null;
}
