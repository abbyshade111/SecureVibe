// Fixture: a cookie with neither HttpOnly nor SameSite set (CONTRACTS §3).
interface FakeResponse {
  cookie(name: string, value: string, opts: Record<string, unknown>): void;
}

export function setFlagCookie(res: FakeResponse): void {
  res.cookie('flag', '1', { secure: true });
}
