/** Sequential evidence ids, unique within a run ("E-0001"; the manifest check uses the "EM" prefix). */
export class EvidenceIds {
  private counter = 0;
  constructor(private readonly prefix = 'E') {}
  next(): string {
    this.counter += 1;
    return `${this.prefix}-${String(this.counter).padStart(4, '0')}`;
  }
}
