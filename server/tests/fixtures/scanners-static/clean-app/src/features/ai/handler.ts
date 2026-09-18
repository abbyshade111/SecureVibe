// Clean fixture: the AI feature reads only the signed-in user's own data (CONTRACTS §1 convention).
import { all } from '../../db/index.js';

export function listConversationsForUser(userId: string): unknown[] {
  return all('SELECT * FROM ai_conversations WHERE user_id = ?', [userId]);
}
