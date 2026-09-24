/**
 * Drives an Express app that is running inside this test process, over a pair of linked in-memory streams that
 * stand in for a TCP connection. Everything above the socket is real: Node's HTTP server and client parse the
 * bytes, so the probes exercise the same code path they use against an app started on a loopback port.
 *
 * This exists because the runtime probes must be testable where binding a listening socket is not allowed
 * (sandboxed CI). `tests/scanners-runtime/dast-harness.test.ts` covers the real spawn-and-listen path when the
 * machine permits it.
 */
import http from 'node:http';
import { Duplex } from 'node:stream';
import { HttpClient, collectResponse, type RawHttpResponse } from '../../../src/scanners/dast/http.js';

/** Enough of a net.Socket for http.Server and http.ClientRequest: the two halves push into each other. */
class LinkedSocket extends Duplex {
  peer: LinkedSocket | undefined;
  readonly remoteAddress = '127.0.0.1';
  readonly remoteFamily = 'IPv4';
  readonly remotePort = 54321;
  readonly localAddress = '127.0.0.1';
  readonly localPort = 8080;
  readonly encrypted = false;

  override _read(): void {}

  override _write(chunk: Buffer, _enc: BufferEncoding, cb: (err?: Error | null) => void): void {
    this.peer?.push(chunk);
    cb();
  }

  override _final(cb: (err?: Error | null) => void): void {
    this.peer?.push(null);
    cb();
  }

  setTimeout(): this {
    return this;
  }

  setNoDelay(): this {
    return this;
  }

  setKeepAlive(): this {
    return this;
  }

  ref(): this {
    return this;
  }

  unref(): this {
    return this;
  }

  address(): { address: string; family: string; port: number } {
    return { address: this.localAddress, family: 'IPv4', port: this.localPort };
  }
}

function socketPair(): [LinkedSocket, LinkedSocket] {
  const client = new LinkedSocket();
  const server = new LinkedSocket();
  client.peer = server;
  server.peer = client;
  return [client, server];
}

export class LoopbackHttpClient extends HttpClient {
  private readonly server: http.Server;

  constructor(requestListener: http.RequestListener, baseUrl = 'http://127.0.0.1:8080') {
    super(baseUrl);
    this.server = http.createServer(requestListener);
  }

  protected override send(
    method: string,
    path: string,
    headers: Record<string, string>,
    body: string | Uint8Array | undefined,
    timeoutMs: number,
  ): Promise<RawHttpResponse> {
    const url = new URL(path.startsWith('http') ? path : `${this.baseUrl}${path}`);
    const [client, serverSide] = socketPair();
    this.server.emit('connection', serverSide);
    return new Promise<RawHttpResponse>((resolve, reject) => {
      const req = http.request(
        {
          // Node only honors createConnection when no agent is set, so `agent` is deliberately left out.
          createConnection: () => client as unknown as import('node:net').Socket,
          host: url.hostname,
          port: url.port || 80,
          path: `${url.pathname}${url.search}`,
          method,
          headers: { Connection: 'close', ...headers },
          timeout: timeoutMs,
        },
        (res) => {
          collectResponse(res).then(resolve, reject);
        },
      );
      req.on('error', reject);
      if (body !== undefined) req.write(body);
      req.end();
    });
  }

  close(): void {
    this.server.close();
  }
}
