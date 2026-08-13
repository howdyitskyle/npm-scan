export class ScanError extends Error {
  constructor(message) {
    super(message);
    this.exitCode = 2;
  }
}
