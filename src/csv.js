export function parseCsv(text) {
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else if (ch !== '\r') {
      field += ch;
    }
  }
  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter((r) => !(r.length === 1 && r[0].trim() === ''));
}

export function parseIocCsv(text) {
  const rows = parseCsv(text);
  if (rows.length < 2) return [];
  const header = rows[0].map((h) => h.trim().toLowerCase());
  const idx = (name) => header.indexOf(name);
  const entries = [];

  const push = (name, versions, seps) => {
    const pkg = (name || '').trim();
    if (!pkg) return;
    for (const sep of seps) {
      for (const v of String(versions ?? '').split(sep)) {
        const ver = v.trim();
        if (!ver || ver.toLowerCase() === 'n/a') continue;
        entries.push([pkg, ver]);
      }
    }
  };

  const eco = idx('ecosystem');
  const pkgCol = idx('package');
  if (eco !== -1 && pkgCol !== -1 && idx('versions') !== -1) {
    for (const r of rows.slice(1)) {
      if ((r[eco] || '').trim().toLowerCase() !== 'npm') continue;
      push(r[pkgCol], r[idx('versions')], ['|']);
    }
  } else if (idx('package_name') !== -1) {
    const vCol = idx('package_versions') !== -1 ? idx('package_versions') : idx('package_version');
    for (const r of rows.slice(1)) {
      push(r[idx('package_name')], r[vCol], [',']);
    }
  } else if (idx('artifact_type') !== -1 && idx('name') !== -1) {
    const vCol = idx('affected_versions');
    for (const r of rows.slice(1)) {
      if ((r[idx('artifact_type')] || '').trim().toLowerCase() !== 'npm package') continue;
      push(r[idx('name')], r[vCol], [',']);
    }
  } else if (idx('type') !== -1 && idx('indicator') !== -1) {
    for (const r of rows.slice(1)) {
      if ((r[idx('type')] || '').trim().toLowerCase() !== 'npm package') continue;
      const ind = (r[idx('indicator')] || '').trim();
      const at = ind.lastIndexOf('@');
      if (at <= 0 || at === ind.length - 1) continue;
      entries.push([ind.slice(0, at), ind.slice(at + 1)]);
    }
  } else if (pkgCol !== -1 && idx('version') !== -1) {
    for (const r of rows.slice(1)) {
      push(r[pkgCol], r[idx('version')], [',']);
    }
  } else if (idx('name') !== -1 && idx('version') !== -1) {
    for (const r of rows.slice(1)) {
      push(r[idx('name')], r[idx('version')], [',']);
    }
  } else {
    throw new Error(`Unrecognized CSV schema (header: ${header.join(',')})`);
  }
  return entries;
}
