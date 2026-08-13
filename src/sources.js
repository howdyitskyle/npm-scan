export const SOURCES = {
  keyv: {
    label: 'DataDog keyv-campaign',
    url: 'https://raw.githubusercontent.com/DataDog/indicators-of-compromise/keyv-campaign/keyv-campaign/malicious-packages.csv',
    cacheFile: 'keyv.csv',
    ref: 'https://github.com/DataDog/indicators-of-compromise/tree/keyv-campaign/keyv-campaign',
  },
  'shai-hulud': {
    label: 'DataDog Shai-Hulud 2.0',
    url: 'https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/consolidated_iocs.csv',
    cacheFile: 'shai-hulud.csv',
    ref: 'https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0',
  },
  axios: {
    label: 'DataDog axios compromise',
    url: 'https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/axios-npm-supply-chain-compromise/iocs.csv',
    cacheFile: 'axios.csv',
    ref: 'https://github.com/DataDog/indicators-of-compromise/tree/main/axios-npm-supply-chain-compromise',
  },
  teampcp: {
    label: 'DataDog TeamPCP',
    url: 'https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/teampcp/iocs.csv',
    cacheFile: 'teampcp.csv',
    ref: 'https://github.com/DataDog/indicators-of-compromise/tree/main/teampcp',
  },
  osv: {
    label: 'OSV (OpenSSF + GitHub Advisory DB)',
    ref: 'https://osv.dev',
  },
};

export const SRC_IDS = Object.keys(SOURCES);

const REFS = new Map(Object.values(SOURCES).map((def) => [def.label, def.ref]));

export function refForLabel(label) {
  return REFS.get(label) || null;
}

export class IndicatorIndex {
  constructor() {
    this._map = new Map();
    this._count = 0;
  }

  add(name, version, source, osvId) {
    const key = `${name}@${version}`;
    let entry = this._map.get(key);
    if (!entry) {
      entry = { sources: new Set(), osv: new Set() };
      this._map.set(key, entry);
      this._count++;
    }
    if (source) entry.sources.add(source);
    if (osvId) entry.osv.add(osvId);
  }

  lookup(name, version) {
    return this._map.get(`${name}@${version}`) || null;
  }

  get size() {
    return this._count;
  }
}
