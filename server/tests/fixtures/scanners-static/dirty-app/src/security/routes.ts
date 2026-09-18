// Fixture stand-in for the real route registry. The handler is typed loosely (not `unknown`) so that
// call-site arrow functions get contextual `req`/`res` types instead of failing `noImplicitAny`.
export function defineRoute(_router: unknown, _spec: unknown, _handler: (req: FixtureRequest, res: FixtureResponse) => unknown): void {}

export interface FixtureRequest {
  body: Record<string, unknown>;
  query: Record<string, unknown>;
  params: Record<string, unknown>;
  valid: { params: Record<string, string>; query: Record<string, string>; body: Record<string, unknown> };
}
export interface FixtureResponse {
  status(code: number): FixtureResponse;
  json(body: unknown): void;
  send(body: unknown): void;
}
export function listRoutes(): unknown[] {
  return [];
}
export function assertAllRoutesRegistered(_app: unknown): void {}
