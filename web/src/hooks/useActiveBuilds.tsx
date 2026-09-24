import { useEffect, useRef, useState } from 'react';
import { STAGE_DESCRIPTIONS, STAGE_IDS, type PipelineRun } from '@shared/pipeline.js';
import { getRun, listProjects, runEventsUrl } from '../lib/api';

/**
 * Every build or check that is running right now, for the bar that follows the owner around.
 *
 * The live figures arrive on each run's event stream, which until now only the Build page listened to: an owner
 * who wandered off mid-build saw nothing to say that something was running and costing them money, and that is
 * the moment a first-time user force-quits a build they have already paid for. This hook holds the run's state
 * above the page: it polls the app list for anything "building", then follows each such run's events for the
 * step it is on and the money it has spent, and lets go when the run ends.
 */
export interface ActiveBuild {
  projectId: string;
  name: string;
  runId: string;
  mode: PipelineRun['mode'];
  /** What the run is doing now, in the words the Build page uses. */
  doing: string;
  step: number;
  steps: number;
  spentUsd: number | null;
}

const POLL_MS = 15_000;

function describe(run: PipelineRun): { doing: string; step: number; steps: number } {
  const stages = run.stages;
  const current = stages.find((s) => s.status === 'running') ?? stages[stages.length - 1];
  const doing = current ? STAGE_DESCRIPTIONS[current.id]?.title ?? current.id : 'Starting';
  const step = current ? Math.max(1, STAGE_IDS.indexOf(current.id) + 1) : 1;
  return { doing, step, steps: STAGE_IDS.length };
}

export function useActiveBuilds(): ActiveBuild[] {
  const [builds, setBuilds] = useState<ActiveBuild[]>([]);
  const streams = useRef(new Map<string, EventSource>());

  useEffect(() => {
    let cancelled = false;

    const update = (runId: string, patch: Partial<ActiveBuild>) =>
      setBuilds((list) => list.map((b) => (b.runId === runId ? { ...b, ...patch } : b)));

    const drop = (runId: string) => {
      streams.current.get(runId)?.close();
      streams.current.delete(runId);
      setBuilds((list) => list.filter((b) => b.runId !== runId));
    };

    const follow = (build: ActiveBuild) => {
      if (streams.current.has(build.runId)) return;
      const es = new EventSource(runEventsUrl(build.runId));
      streams.current.set(build.runId, es);
      es.addEventListener('progress', (ev) => {
        try {
          const payload = JSON.parse((ev as MessageEvent<string>).data) as { type?: string; data?: { estimatedCostUsd?: number } };
          if (payload.type === 'spend' && typeof payload.data?.estimatedCostUsd === 'number') update(build.runId, { spentUsd: payload.data.estimatedCostUsd });
          if (payload.type === 'stage' || payload.type === 'done') {
            getRun(build.runId)
              .then((run) => (run.status === 'running' ? update(build.runId, describe(run)) : drop(build.runId)))
              .catch(() => undefined);
          }
        } catch {
          // a message this bar cannot read is not a reason to stop following the run
        }
      });
      es.onerror = () => undefined; // the browser retries; the poll below is the fallback
    };

    const poll = async () => {
      try {
        const projects = await listProjects();
        if (cancelled) return;
        const building = projects.filter((p) => p.status === 'building' && p.lastRunId && !p.archivedAt);
        const seen = new Set<string>();
        for (const p of building) {
          const runId = p.lastRunId!;
          seen.add(runId);
          let run: PipelineRun;
          try {
            run = await getRun(runId);
          } catch {
            continue;
          }
          if (cancelled) return;
          if (run.status !== 'running') continue;
          const next: ActiveBuild = {
            projectId: p.id,
            name: p.name,
            runId,
            mode: run.mode,
            ...describe(run),
            spentUsd: run.llmUsage?.estimatedCostUsd ?? null,
          };
          setBuilds((list) => (list.some((b) => b.runId === runId) ? list.map((b) => (b.runId === runId ? { ...b, ...next, spentUsd: b.spentUsd ?? next.spentUsd } : b)) : [...list, next]));
          follow(next);
        }
        for (const runId of [...streams.current.keys()]) if (!seen.has(runId)) drop(runId);
      } catch {
        // signed out, or the server is away: nothing to show
      }
    };

    void poll();
    const timer = setInterval(() => void poll(), POLL_MS);
    const streamsAtMount = streams.current;
    return () => {
      cancelled = true;
      clearInterval(timer);
      for (const es of streamsAtMount.values()) es.close();
      streamsAtMount.clear();
    };
  }, []);

  return builds;
}
