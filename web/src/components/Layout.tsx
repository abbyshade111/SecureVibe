import type { ReactNode } from 'react';
import { Link, NavLink } from 'react-router';
import { signOut } from '../lib/api';

async function handleSignOut() {
  await signOut();
  // A full page load shows SecureVibe's "open the startup link" page, since this browser no longer has a session.
  window.location.assign('/');
}

export function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="sv-shell">
      <a className="sv-skip-link" href="#sv-main-content">
        Skip to main content
      </a>
      <header className="sv-topbar">
        <div className="sv-topbar-inner">
          <Link className="sv-brand" to="/" aria-label="SecureVibe home">
            <img className="sv-brand-mark" src="/brand/securevibe-favicon.svg" alt="" width={30} height={30} />
            SecureVibe
          </Link>
          <nav className="sv-nav" aria-label="Main">
            <NavLink to="/" end>
              My apps
            </NavLink>
            <NavLink to="/dashboard">Dashboard</NavLink>
            <NavLink to="/security">Security</NavLink>
            <NavLink to="/settings">Settings</NavLink>
            <button type="button" className="sv-btn sv-btn-secondary sv-btn-sm" onClick={() => void handleSignOut()}>
              Sign out
            </button>
          </nav>
        </div>
      </header>
      <main id="sv-main-content" className="sv-main" tabIndex={-1}>
        {children}
      </main>
      <footer className="sv-footer">
        SecureVibe runs entirely on this computer. Nothing you build is uploaded anywhere except to the AI
        service you configure.
      </footer>
    </div>
  );
}
