/** The runtime probes' HTTP client refuses any host that is not this computer: the certificate check it turns off is only safe there. */
import { describe, expect, it } from 'vitest';
import { isLoopbackHost, sendOverNodeHttp } from '../../src/scanners/dast/http.js';

describe('the probes\' HTTP client', () => {
  it('knows which hosts are this computer', () => {
    for (const h of ['127.0.0.1', '127.0.0.2', 'localhost', 'LOCALHOST', '::1', '[::1]']) expect(isLoopbackHost(h), h).toBe(true);
    for (const h of ['example.com', '10.0.0.5', '192.168.1.1', '0.0.0.0', '127.0.0.1.evil.com', 'localhost.evil.com']) expect(isLoopbackHost(h), h).toBe(false);
  });

  it('refuses to send anywhere else before touching the network', async () => {
    await expect(sendOverNodeHttp(new URL('https://example.com/healthz'), 'GET', {}, undefined, 1_000)).rejects.toThrow(/only talk to an app on this computer/);
    await expect(sendOverNodeHttp(new URL('https://10.0.0.5:3000/'), 'GET', {}, undefined, 1_000)).rejects.toThrow(/only talk to an app on this computer/);
  });
});
