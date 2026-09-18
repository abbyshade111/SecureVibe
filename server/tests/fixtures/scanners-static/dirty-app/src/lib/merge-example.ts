// Fixture: mass assignment and a for-in copy loop that does not guard __proto__ (CONTRACTS §3).
export function updateProfile(req: { body: Record<string, unknown> }, profile: Record<string, unknown>): void {
  Object.assign(profile, req.body);
}

export function assignSettings(target: Record<string, unknown>, req: { headers: Record<string, unknown> }): void {
  for (const key in req.headers) {
    target[key] = req.headers[key];
  }
}
