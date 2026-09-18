/** Dependencies every API route module needs, assembled once in app.ts and threaded through `buildApiRouter`. */
import type { Frameworks, Knowledge, ProviderFor } from '../integration.js';
import type { SecureVibeConfig } from '../config.js';
import type { RunBusRegistry } from '../pipeline/bus.js';
import type { Logger } from '../security/logger.js';
import type { SessionManager } from '../security/token.js';
import type { BuildApprovals } from './approvals.js';
import type { PreviewManager } from '../preview/index.js';
import type { ProjectStore } from '../store/index.js';

export interface ApiDeps {
  config: SecureVibeConfig;
  sessions: SessionManager;
  logger: Logger;
  store: ProjectStore;
  knowledge: Knowledge;
  frameworks: Frameworks;
  getProvider: ProviderFor;
  busRegistry: RunBusRegistry;
  /** Open build approvals; created by `buildApiRouter` when not supplied. */
  approvals: BuildApprovals;
  /** Running app previews; created by `buildApiRouter` when not supplied. */
  previews: PreviewManager;
}
