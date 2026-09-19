/**
 * `GET /api/security`: every app at once, for someone whose job is the security of all of them rather than the
 * building of one.
 *
 * The hard part of this view is not gathering the numbers, it is refusing to add them up. One app is a note-taker
 * on a laptop; the next is going on the internet with other people's health records. A total across both is a
 * number nobody can act on, and it reads as reassurance. So nothing here is summed across apps: each app keeps its
 * own counts beside the two things that make them mean anything — where it runs and what level it is measured
 * against — and the only figures that span apps count *apps*, which are comparable.
 *
 * Three rules make the counts honest, each one a bug this project has already had somewhere else:
 *
 *  - **Counts come only from a run that ran every check.** A single-check re-run holds findings from that check
 *    alone, so counting its run record would show an app improving because less was looked at. Later partial runs
 *    are reported as a number of them, not folded in.
 *  - **A missing number is never a zero.** An app that was never built, or never fully checked, says so.
 *  - **No ceiling on how far back to look.** The run that last ran every check may be many re-runs ago; stopping
 *    early would make an app that has been checked look like one that never was.
 */
import { Router } from 'express';
import { SecurityAcrossAppsResponseSchema, type AppSecurityRow, type SecurityAcrossAppsResponse } from '@shared/api.js';
import { isOpen, type Finding } from '@shared/findings.js';
import { currentFindings } from './findings-view.js';
import { isUploadedApp, type Project } from '@shared/project.js';
import type { PipelineRun } from '@shared/pipeline.js';
import type { ApiDeps } from './types.js';

/** Severities in the order a person reads them; also the order of the keys in every count. */
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

/** An app is worth someone's attention when something serious is open, or when nobody knows what it holds. */
function needsAttention(row: AppSecurityRow): boolean {
  if (row.noCounts) return true;
  const open = row.open ?? {};
  return (open.critical ?? 0) > 0 || (open.high ?? 0) > 0;
}

function countBy<T extends string>(findings: Finding[], key: (f: Finding) => T): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) out[key(f)] = (out[key(f)] ?? 0) + 1;
  return out;
}

function rowFor(deps: ApiDeps, project: Project): AppSecurityRow {
  const uploaded = isUploadedApp(project);
  const base = {
    projectId: project.id,
    name: project.name,
    origin: uploaded ? ('uploaded' as const) : ('generated' as const),
    exposure: project.profile?.deployment?.target ?? ('unknown' as const),
    ...(project.profile?.users?.audience ? { audience: project.profile.users.audience } : {}),
    ...(project.design?.applicability.targetLevel ? { targetLevel: project.design.applicability.targetLevel } : {}),
    decided: { accepted: 0, falsePositive: 0 },
    whoCanFix: {},
  };

  const current = currentFindings(deps.store, project);
  const run = current.lastFullRun;
  const since = {
    // Each of these checks has been run again since everything was last checked together, so its numbers are newer
    // than that run's — which is the point of re-running one after fixing what it complained about.
    checksRerunSince: current.checksRerunSince,
    rebuilt: Boolean(run && project.lastRunId && project.lastRunId !== run.id && !deps.store.readRun(project.id, project.lastRunId)?.partial),
    answersChanged: project.designStale,
  };

  if (!run) {
    const reason = current.unreadable ? 'checks-unreadable' : project.lastRunId ? 'never-fully-checked' : 'never-built';
    return { ...base, noCounts: reason, since };
  }

  const findings = current.findings;
  const open = findings.filter(isOpen);
  const counts: Record<string, number> = {};
  for (const severity of SEVERITIES) {
    const n = open.filter((f) => f.severity === severity).length;
    if (n > 0) counts[severity] = n;
  }

  return {
    ...base,
    lastFullCheck: {
      runId: run.id,
      ...(run.finishedAt ? { finishedAt: run.finishedAt } : {}),
      status: run.status,
      ...(run.compliance?.overall.rating ? { rating: run.compliance.overall.rating } : {}),
    },
    open: counts,
    decided: {
      accepted: findings.filter((f) => f.status === 'accepted').length,
      falsePositive: findings.filter((f) => f.status === 'false-positive').length,
    },
    whoCanFix: countBy(open, (f) => f.whoCanFix),
    since,
  };
}

export function securityRouter(deps: ApiDeps): Router {
  const router = Router();

  router.get('/security', (_req, res) => {
    // The listing is a light record without the profile, the runs or the owner's decisions, and every one of those
    // is needed here, so each project is read in full. They are small JSON files.
    const apps = deps.store
      .list()
      .map((item) => deps.store.get(item.id))
      .filter((project): project is Project => project !== undefined)
      .map((project) => rowFor(deps, project))
      // Worst first: never-checked apps, then the ones with something serious open, then by how much is open.
      .sort((a, b) => {
        const attention = Number(needsAttention(b)) - Number(needsAttention(a));
        if (attention !== 0) return attention;
        const weight = (row: AppSecurityRow): number => (row.open?.critical ?? 0) * 1000 + (row.open?.high ?? 0) * 100 + (row.open?.medium ?? 0) * 10 + (row.open?.low ?? 0);
        return weight(b) - weight(a);
      });

    const body: SecurityAcrossAppsResponse = {
      apps,
      appsNeedingAttention: apps.filter(needsAttention).length,
      appsNeverFullyChecked: apps.filter((a) => a.noCounts).length,
      generatedAt: new Date().toISOString(),
    };
    res.json(SecurityAcrossAppsResponseSchema.parse(body));
  });

  return router;
}
