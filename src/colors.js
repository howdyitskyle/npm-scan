export let useColor = process.stdout.isTTY && !process.env.NO_COLOR;

export function setUseColor(v) {
  useColor = v;
}

const c = (code) => (s) => (useColor ? `\u001b[${code}m${s}\u001b[0m` : String(s));

export const bold = c('1');
export const dim = c('2');
export const hex = (r, g, b) => (s) =>
  useColor ? `\u001b[38;2;${r};${g};${b}m${s}\u001b[0m` : String(s);

/* neon palette (matches the TUI) */
export const red = hex(255, 77, 77);
export const green = hex(0, 255, 156);
export const yellow = hex(255, 209, 102);
export const cyan = hex(0, 212, 255);
export const magenta = hex(255, 46, 196);
export const dimGray = hex(90, 90, 110);

/* OSC 8 terminal hyperlink: \x1b]8;;URL\x07 label \x1b]8;;\x07 */
export function link(url, label) {
  const text = label ?? String(url);
  if (!useColor) return text;
  return `\u001b]8;;${url}\u0007${text}\u001b]8;;\u0007`;
}

export function stripAnsi(s) {
  return String(s).replace(/\u001b\[[0-9;]*m|\u001b\][^\u0007\u001b]*\u0007/g, '');
}
