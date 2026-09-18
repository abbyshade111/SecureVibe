// Fixture: React dangerouslySetInnerHTML (CONTRACTS §3).
export function Preview({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
