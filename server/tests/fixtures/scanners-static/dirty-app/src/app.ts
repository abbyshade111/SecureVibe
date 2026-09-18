// Fixture: several app-level misconfigurations (CONTRACTS §3).
import express from 'express';
import helmet from 'helmet';

declare function cors(opts?: Record<string, unknown>): express.RequestHandler;

const app = express();

app.set('trust proxy', true);

app.use(
  helmet({
    contentSecurityPolicy: false,
  }),
);

app.use(
  cors({
    origin: '*',
    credentials: true,
  }),
);

app.use(
  cors({
    origin: '*',
  }),
);

app.use(
  express.static('public', {
    dotfiles: 'allow',
  }),
);

export default app;
