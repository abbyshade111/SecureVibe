import { Link } from 'react-router';

export function NotFoundPage() {
  return (
    <div className="sv-card">
      <h1>Page not found</h1>
      <p>We could not find that page.</p>
      <Link className="sv-btn" to="/">
        Back to my apps
      </Link>
    </div>
  );
}
