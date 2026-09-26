// A small app whose only sign-in is through another service (OpenID Connect), written with Node's
// built-in modules so it runs inside the fence. It does what a careful app should: `state`, PKCE,
// a `nonce`, and an RS256 signature verified against the provider's published keys, with `iss`,
// `aud`, and `exp` checked. `flaws.json`, if present, lists checks to leave out, so the same app
// can show what `sv` finds when one is missing: "state", "pkce", "nonce", "aud", "signature".
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');

const ISSUER = process.env.OIDC_ISSUER;
const CLIENT_ID = process.env.OIDC_CLIENT_ID;
const CLIENT_SECRET = process.env.OIDC_CLIENT_SECRET;
const flaws = new Set(fs.existsSync('flaws.json') ? JSON.parse(fs.readFileSync('flaws.json', 'utf8')) : []);
const sessions = new Map();
const b64 = (b) => Buffer.from(b).toString('base64url');
let provider;

async function discover() {
  if (!provider) {
    const config = await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json();
    const jwks = await (await fetch(config.jwks_uri)).json();
    provider = { config, jwks };
  }
  return provider;
}

function session(req, res) {
  const sid = /(?:^|; )sid=([^;]+)/.exec(req.headers.cookie || '')?.[1];
  if (sid && sessions.has(sid)) return sessions.get(sid);
  const id = b64(crypto.randomBytes(24));
  const s = { id };
  sessions.set(id, s);
  res.setHeader('set-cookie', `sid=${id}; Path=/; HttpOnly; SameSite=Lax`);
  return s;
}

function verify(idToken, s, jwks) {
  const [h, p, sig] = idToken.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url'));
  const claims = JSON.parse(Buffer.from(p, 'base64url'));
  if (!flaws.has('signature')) {
    if (header.alg !== 'RS256') return 'algorithm';
    const jwk = jwks.keys.find((k) => k.kid === header.kid);
    if (!jwk) return 'no key';
    const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    if (!crypto.verify('sha256', Buffer.from(`${h}.${p}`), key, Buffer.from(sig || '', 'base64url'))) return 'signature';
  }
  if (claims.iss !== ISSUER) return 'issuer';
  if (!flaws.has('aud') && claims.aud !== CLIENT_ID) return 'audience';
  if (claims.exp < Date.now() / 1000) return 'expired';
  if (!flaws.has('nonce') && claims.nonce !== s.nonce) return 'nonce';
  return null;
}

http
  .createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const s = session(req, res);
    try {
      if (url.pathname === '/') return res.end('Notes. Sign in with the provider at /login/google.');
      if (url.pathname === '/login/google') {
        const { config } = await discover();
        s.state = b64(crypto.randomBytes(16));
        s.nonce = b64(crypto.randomBytes(16));
        s.verifier = b64(crypto.randomBytes(32));
        const to = new URL(config.authorization_endpoint);
        const params = {
          response_type: 'code',
          client_id: CLIENT_ID,
          redirect_uri: `http://${req.headers.host}/callback`,
          scope: 'openid email',
          state: s.state,
          nonce: s.nonce,
        };
        if (!flaws.has('pkce')) {
          params.code_challenge = b64(crypto.createHash('sha256').update(s.verifier).digest());
          params.code_challenge_method = 'S256';
        }
        for (const [k, v] of Object.entries(params)) to.searchParams.set(k, v);
        res.writeHead(302, { location: to.toString() });
        return res.end();
      }
      if (url.pathname === '/callback') {
        const { config, jwks } = await discover();
        if (!flaws.has('state') && url.searchParams.get('state') !== s.state) {
          res.writeHead(400);
          return res.end('state');
        }
        const body = new URLSearchParams({
          grant_type: 'authorization_code',
          code: url.searchParams.get('code') || '',
          redirect_uri: `http://${req.headers.host}/callback`,
        });
        if (!flaws.has('pkce') && s.verifier) body.set('code_verifier', s.verifier);
        const answer = await fetch(config.token_endpoint, {
          method: 'POST',
          headers: {
            'content-type': 'application/x-www-form-urlencoded',
            authorization: `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')}`,
          },
          body,
        });
        const tokens = await answer.json();
        const wrong = tokens.id_token ? verify(tokens.id_token, s, jwks) : 'no token';
        if (wrong) {
          res.writeHead(401);
          return res.end(`refused: ${wrong}`);
        }
        s.user = JSON.parse(Buffer.from(tokens.id_token.split('.')[1], 'base64url')).sub;
        res.writeHead(302, { location: '/account' });
        return res.end();
      }
      if (url.pathname === '/account') {
        if (!s.user) {
          res.writeHead(302, { location: '/login/google' });
          return res.end();
        }
        return res.end(`Signed in as ${s.user}.`);
      }
      res.writeHead(404);
      res.end('not found');
    } catch (e) {
      res.writeHead(500);
      res.end('error');
    }
  })
  .listen(Number(process.env.PORT || 8080), '0.0.0.0');
