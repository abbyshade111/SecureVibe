// Fixture: the AI feature reads a table without limiting it to the signed-in user (ast-checks §
// ai-context-user-scoped). No SAST rule targets this pattern directly, so it adds no SAST findings.
import { all } from '../../db/index.js';

export function listAllConversations(): unknown[] {
  return all('SELECT * FROM ai_conversations');
}
