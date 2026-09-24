import { Link, useLocation } from 'react-router';
import { useActiveBuilds } from '../hooks/useActiveBuilds';

/** The strip under the top bar that says a build is running, what it is doing and what it has spent, on every page. */
export function ActiveBuildBar() {
  const builds = useActiveBuilds();
  const location = useLocation();
  if (builds.length === 0) return null;
  return (
    <div className="sv-active-builds" role="status" aria-live="polite">
      {builds.map((b) => {
        const here = location.pathname === `/projects/${b.projectId}/build`;
        const what = b.mode === 'verify-only' ? 'Checking' : 'Building';
        return (
          <div key={b.runId} className="sv-active-build">
            <img className="sv-mascot" src="/brand/securevibe-mascot-building.svg" alt="" width={22} height={22} />
            <span>
              <strong>
                {what} {b.name}
              </strong>{' '}
              — {b.doing.toLowerCase()} (step {b.step} of {b.steps})
              {b.spentUsd !== null && b.spentUsd > 0 ? ` · $${b.spentUsd.toFixed(2)} spent so far` : b.mode === 'full' ? ' · nothing spent yet' : ''}
            </span>
            {!here && (
              <Link className="sv-btn sv-btn-secondary sv-btn-sm" to={`/projects/${b.projectId}/build?run=${encodeURIComponent(b.runId)}`}>
                Watch it
              </Link>
            )}
          </div>
        );
      })}
    </div>
  );
}
