export function usd(amount: number): string {
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 2 }).format(
    amount,
  );
}

export function usdRange(low: number, high: number): string {
  if (Math.abs(low - high) < 0.01) return usd(low);
  return `${usd(low)} – ${usd(high)}`;
}

export function minutesRange(low: number, high: number): string {
  if (low === high) return `about ${low} minute${low === 1 ? '' : 's'}`;
  return `${low}–${high} minutes`;
}

export function formatDate(iso: string | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function formatDateOnly(iso: string | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString(undefined, { dateStyle: 'medium' });
}

/** "government-id" -> "Government id" ; used only as a last-resort label when copy is missing. */
export function humanize(value: string): string {
  const spaced = value.replace(/[-_]+/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2');
  return spaced.charAt(0).toUpperCase() + spaced.slice(1).toLowerCase();
}

export function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}
