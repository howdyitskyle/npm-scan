export function matchKindLabel(m) {
  if (m.direct === undefined || m.direct === null) return null;
  if (m.direct) return 'Direct dependency';
  return m.via && m.via.length > 0 ? `Transitive via ${m.via.join(', ')}` : 'Transitive';
}

export function severityLabel(sev) {
  if (!sev) return null;
  const value = sev.score ?? sev.severity ?? sev.vector;
  return value ? `${value} (${sev.type || 'CVSS'})` : null;
}
