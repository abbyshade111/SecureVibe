// Fixture: a catastrophic-backtracking pattern and a regex built from request data (CONTRACTS §3).
export const CATASTROPHIC = /^(a+)+$/;

export function matchUserPattern(req: { query: { term: string } }): RegExp {
  return new RegExp(req.query.term);
}
