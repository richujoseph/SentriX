// Must match FALLBACK_PREFIX in backend/app/llm/summarizer.py.
export const FALLBACK_PREFIX = "[Automatic summary unavailable]";

export function isFallbackSummary(summary) {
  return summary?.startsWith(FALLBACK_PREFIX) ?? false;
}

export function stripFallbackPrefix(summary) {
  return isFallbackSummary(summary) ? summary.slice(FALLBACK_PREFIX.length).trim() : summary;
}
