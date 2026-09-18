// Fixture: an open redirect and an email header built from request data (CONTRACTS §3).
interface FakeRequest {
  query: { next?: string };
  body: { to?: string };
}
interface FakeResponse {
  redirect(target: string): void;
}
const mailer = {
  sendMail: (_opts: { to?: string; subject: string }): void => {},
};

export async function redirectHandler(req: FakeRequest, res: FakeResponse): Promise<void> {
  res.redirect(req.query.next as string);
}

export async function contactHandler(req: FakeRequest): Promise<void> {
  mailer.sendMail({
    to: req.body.to,
    subject: 'Contact',
  });
}
