/**
 * Every test runs against a throw-away SECUREVIBE_HOME, so nothing a test does (AI audit lines from the scripted
 * provider, prompts, settings) ends up in the owner's real workspace. Tests that need their own home still pass one.
 */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env['SECUREVIBE_HOME'] = mkdtempSync(join(tmpdir(), 'securevibe-test-home-'));
