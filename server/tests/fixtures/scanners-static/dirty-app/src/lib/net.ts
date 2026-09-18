// Fixture: outbound HTTP that bypasses src/lib/http-client.ts, with certificate checks off (CONTRACTS §3).
import https from 'node:https';

export function fetchInsecure(url: string): void {
  https.get(
    url,
    {
      rejectUnauthorized: false,
    },
    () => {},
  );
}

export async function callExternal(userUrl: string): Promise<Response> {
  return fetch(userUrl);
}
