// A test OpenID Connect provider for `sv`, run on the fenced network in a stock Node image. It signs
// people in without asking anything, and it can be told to get the next ID token wrong in one
// particular way, which is its whole purpose: a provider made for testing an app's sign-in has to
// be able to misbehave on purpose, and no ready-made one does.
//
// Built-in modules only: the fence has no route to a package registry.
//
// Environment: ISSUER (its own address, as the app will reach it), PORT, CLIENT_ID, CLIENT_SECRET.
//
// `POST /_sv/mode` with `mode=<name>` sets how the next ID token is made, once:
//   normal       as it should be
//   wrong-nonce  a `nonce` that is not the one the app sent
//   wrong-aud    issued for another client
//   unsigned     `alg: none`, no signature
//   wrong-key    signed with a key the provider never published
//   wrong-iss    the sign-in's `iss` parameter names another provider (used up at /authorize, since
//                an app that refuses it never asks for a token)
//   wrong-token-iss  an ID token whose `iss` claim names another provider
//   other-person     a different person (another `sub`) who has the same email address
//   new-email        the same person (the same `sub`) after their email address changed
import http from 'node:http';
import crypto from 'node:crypto';

const ISSUER = process.env.ISSUER;
const PORT = Number(process.env.PORT || 9000);
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

const key = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const stranger = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const KID = 'sv-1';
// A provider that does not exist, named where a mix-up attack would name one.
const OTHER_ISSUER = 'http://sv-other-idp.invalid';
// Each request the app made, as its method, path, and the names of its query parameters, never their
// values (a code, a state, a token), for `sv` to keep beside the report (ADR-082). `GET /_sv/requests`
// hands it over; at most `MOST_REQUESTS`, then counted.
const requests = [];
const MOST_REQUESTS = 500;
let requestsLeftOut = 0;
const codes = new Map(); // code -> what the sign-in asked for
const tokens = new Map(); // access token -> { sub, email }
let mode = 'normal';

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const json = (res, status, body) => {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
};

function idToken(claims, how) {
  const header = { alg: how === 'unsigned' ? 'none' : 'RS256', typ: 'JWT', kid: KID };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  if (how === 'unsigned') return `${input}.`;
  const signer = how === 'wrong-key' ? stranger.privateKey : key.privateKey;
  return `${input}.${b64url(crypto.sign('sha256', Buffer.from(input), signer))}`;
}

function clientFrom(req, form) {
  const basic = /^Basic (.+)$/i.exec(req.headers.authorization || '');
  if (basic) {
    const [id, secret] = Buffer.from(basic[1], 'base64').toString().split(':');
    return { id: decodeURIComponent(id), secret: decodeURIComponent(secret || '') };
  }
  return { id: form.get('client_id'), secret: form.get('client_secret') };
}

function body(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => resolve(data));
  });
}

http
  .createServer(async (req, res) => {
    const url = new URL(req.url, ISSUER);
    const path = url.pathname;
    if (req.method === 'GET' && path === '/_sv/requests') {
      return json(res, 200, { requests, left_out: requestsLeftOut });
    }
    if (!path.startsWith('/_sv/')) {
      if (requests.length < MOST_REQUESTS) {
        requests.push({ method: req.method, path, query: [...new Set(url.searchParams.keys())] });
      } else {
        requestsLeftOut += 1;
      }
    }
    if (req.method === 'GET' && path === '/.well-known/openid-configuration') {
      return json(res, 200, {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        userinfo_endpoint: `${ISSUER}/userinfo`,
        jwks_uri: `${ISSUER}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        code_challenge_methods_supported: ['S256', 'plain'],
        scopes_supported: ['openid', 'email', 'profile'],
        // RFC 9207: the sign-in's return carries `iss`, and a client library that reads this checks it.
        authorization_response_iss_parameter_supported: true,
      });
    }
    if (req.method === 'GET' && path === '/jwks') {
      const jwk = key.publicKey.export({ format: 'jwk' });
      return json(res, 200, { keys: [{ ...jwk, kid: KID, alg: 'RS256', use: 'sig' }] });
    }
    if (req.method === 'GET' && path === '/authorize') {
      const q = url.searchParams;
      const redirect = q.get('redirect_uri');
      if (q.get('client_id') !== CLIENT_ID || !redirect) return json(res, 400, { error: 'invalid_request' });
      const code = b64url(crypto.randomBytes(24));
      codes.set(code, {
        redirect,
        nonce: q.get('nonce'),
        challenge: q.get('code_challenge'),
        method: q.get('code_challenge_method') || 'plain',
      });
      const back = new URL(redirect);
      back.searchParams.set('code', code);
      if (q.get('state') !== null) back.searchParams.set('state', q.get('state'));
      const mixed = mode === 'wrong-iss';
      if (mixed) mode = 'normal';
      back.searchParams.set('iss', mixed ? OTHER_ISSUER : ISSUER);
      res.writeHead(302, { location: back.toString() });
      return res.end();
    }
    if (req.method === 'POST' && path === '/token') {
      const form = new URLSearchParams(await body(req));
      const client = clientFrom(req, form);
      if (client.id !== CLIENT_ID || (CLIENT_SECRET && client.secret !== CLIENT_SECRET)) {
        return json(res, 401, { error: 'invalid_client' });
      }
      const grant = codes.get(form.get('code'));
      codes.delete(form.get('code')); // a code is used once, whatever happens
      if (!grant || grant.redirect !== form.get('redirect_uri')) return json(res, 400, { error: 'invalid_grant' });
      if (grant.challenge) {
        const verifier = form.get('code_verifier') || '';
        const made =
          grant.method === 'S256' ? b64url(crypto.createHash('sha256').update(verifier).digest()) : verifier;
        if (made !== grant.challenge) return json(res, 400, { error: 'invalid_grant' });
      }
      const how = mode;
      mode = 'normal';
      const now = Math.floor(Date.now() / 1000);
      const claims = {
        iss: how === 'wrong-token-iss' ? OTHER_ISSUER : ISSUER,
        sub: how === 'other-person' ? 'sv-oidc-other-person' : 'sv-oidc-user',
        aud: how === 'wrong-aud' ? 'some-other-client' : CLIENT_ID,
        exp: now + 300,
        iat: now,
        auth_time: now,
        email: how === 'new-email' ? 'sv-oidc-user-new@example.test' : 'sv-oidc-user@example.test',
        email_verified: true,
      };
      if (grant.nonce !== null) claims.nonce = how === 'wrong-nonce' ? `not-${grant.nonce}` : grant.nonce;
      else if (how === 'wrong-nonce') claims.nonce = 'a-nonce-nobody-sent';
      const access = b64url(crypto.randomBytes(24));
      tokens.set(access, { sub: claims.sub, email: claims.email });
      return json(res, 200, {
        access_token: access,
        token_type: 'Bearer',
        expires_in: 300,
        id_token: idToken(claims, how),
      });
    }
    if (req.method === 'GET' && path === '/userinfo') {
      const bearer = /^Bearer (.+)$/i.exec(req.headers.authorization || '');
      const who = bearer && tokens.get(bearer[1]);
      if (!who) return json(res, 401, { error: 'invalid_token' });
      return json(res, 200, { sub: who.sub, email: who.email, email_verified: true });
    }
    if (req.method === 'POST' && path === '/_sv/mode') {
      const wanted = new URLSearchParams(await body(req)).get('mode');
      const modes = [
        'normal', 'wrong-nonce', 'wrong-aud', 'unsigned', 'wrong-key', 'wrong-iss', 'wrong-token-iss',
        'other-person', 'new-email',
      ];
      if (!modes.includes(wanted)) {
        return json(res, 400, { error: 'unknown mode' });
      }
      mode = wanted;
      return json(res, 200, { mode });
    }
    // The process id says which server answered: a test that started one on a port another test's
    // server had already taken would otherwise go on talking to that one.
    if (req.method === 'GET' && path === '/_sv/health') return json(res, 200, { ok: true, pid: process.pid });
    json(res, 404, { error: 'not_found' });
  })
  .listen(PORT, '0.0.0.0');
