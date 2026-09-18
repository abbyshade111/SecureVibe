// Clean fixture: template conventions (CONTRACTS §1) — nonce-based CSP, no CORS, no dotfiles, trust proxy off.
import express from 'express';
import helmet from 'helmet';
import { assertAllRoutesRegistered } from './security/routes.js';
import { router as notesRouter } from './features/notes/routes.js';

const app = express();

app.set('trust proxy', 0);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'nonce-{n}'", "'strict-dynamic'"],
        'style-src': ["'self'", "'nonce-{n}'"],
        'object-src': ["'none'"],
        'base-uri': ["'none'"],
        'frame-ancestors': ["'none'"],
        'form-action': ["'self'"],
      },
    },
  }),
);

app.use(express.static('public'));
app.use(notesRouter);
assertAllRoutesRegistered(app);

export default app;
