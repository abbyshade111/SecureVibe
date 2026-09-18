// Fixture: XML parsing with external entities enabled (CONTRACTS §3).
declare function parseXml(xml: string, opts: Record<string, unknown>): unknown;

export function parseUploadedXml(xml: string): unknown {
  return parseXml(xml, { noent: true });
}
