# Club evenings

I run a small club and want a simple web app for members.

- Members sign in with their email address and password at `/login` (a form with fields `email` and
  `password`). They sign out with a button that posts to `/logout`.
- After signing in, a member lands on `/account`, which shows their own notes and a way to sign out.
- Members can write private notes: a form that posts a field `text` to `/notes`, which saves the note
  and takes them to the note's own page at `/notes/<id>`.
- There is one seat at the next club evening. A member books it with a button that posts to `/book`;
  the page then says "Booked". When the seat is gone, it says so.
- Members can ask an assistant a question: a form posting a field `question` to `/ask`. The app sends
  the question to an OpenAI-compatible chat completions API (the address is in the environment
  variable `OPENAI_BASE_URL`, which ends in `/v1`, and the key in `OPENAI_API_KEY`; use the model
  `gpt-4o-mini`) and shows the answer on the page.
- Admins have a page at `/admin` listing all members. Admins can post an announcement: a form posting a
  field `text` to `/announcements`. Announcements show on the home page `/`.
- Anyone may see the home page `/`.

Technical requirements (these are fixed, because of where the app will be tested):

- Python 3.12, **standard library only** (no pip packages: nothing can be installed). One file,
  `app.py`, using `http.server`, listening on `0.0.0.0` at the port in the environment variable `PORT`
  (default 8080). Store data in SQLite at the path in the environment variable `CLUB_DB` (default
  `/tmp/club.db`; the app's own folder is read-only when it runs).
- I check my apps with SecureVibe (`sv`), which runs them in a container and tests them while they run.
  It needs a `securevibe.toml` in this folder describing the app; its specification is below.
