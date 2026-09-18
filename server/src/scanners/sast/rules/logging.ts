/**
 * Logging rules: sensitive fields in log calls, console.log in server code, and security TODOs.
 */
import ts from 'typescript';
import { calleeName, calleeTail, isLiteralish, propertyName, RAW_REQ_TAINT, text } from '../engine.js';
import { defineRule, SENSITIVE_LOG_KEY } from './base.js';
import { ejsSecurityTodos, SECURITY_WORDS } from './views.js';

const LOG_RECEIVER = /^(logger|log|console|pino|req\.log|this\.logger|this\.log|app\.log)$/;
const LOG_METHODS = new Set(['log', 'info', 'warn', 'error', 'debug', 'trace', 'fatal', 'child']);
const SENSITIVE_IDENTIFIER = /(password|passwd|secret|token|apiKey|api_key|totp|otp|privateKey|private_key|recoveryCode|authorization|cookie)/i;
/** Token *counts* (usage accounting) are not tokens; logging them is expected. */
const USAGE_COUNT = /^(input|output|cache\w*|max|total|daily|prompt|completion|used|remaining)_?tokens?$|tokens?_?(used|count|limit|budget|remaining)$/i;
const TODO = /\b(TODO|FIXME|XXX|HACK)\b/;

function isLogCall(node: ts.CallExpression): boolean {
  const tail = calleeTail(node);
  if (!tail) return false;
  if (tail === 'emit' && ts.isIdentifier(node.expression)) return true;
  if (!LOG_METHODS.has(tail) || !ts.isPropertyAccessExpression(node.expression)) return false;
  return LOG_RECEIVER.test(node.expression.expression.getText());
}

export const logSensitiveField = defineRule({
  id: 'sast.log-sensitive-field',
  title: 'A secret or personal value is written to the log',
  severity: 'medium',
  confidence: 'high',
  cwe: ['CWE-532'],
  asvs: ['V16.2.5'],
  sbd: ['MT-01'],
  exploitability: 'theoretical',
  description: 'A log or security-event call includes a password, token, API key, cookie, raw request body or similar value.',
  impact: 'Logs are copied, shared and kept for a long time; a secret in a log is a secret everyone with log access has.',
  fix: 'Log identifiers and outcomes only (user id, route, reason). Never log credentials, tokens or whole request bodies.',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (!ts.isCallExpression(node) || !isLogCall(node)) return;
    const offenders: string[] = [];
    for (const arg of node.arguments) {
      if (ts.isObjectLiteralExpression(arg)) {
        for (const p of arg.properties) {
          if (ts.isShorthandPropertyAssignment(p)) {
            if (SENSITIVE_LOG_KEY.test(p.name.text) && p.name.text !== 'req' && !USAGE_COUNT.test(p.name.text)) offenders.push(p.name.text);
          } else if (ts.isPropertyAssignment(p)) {
            const name = propertyName(p.name) ?? '';
            const value = text(p.initializer, file);
            if (isLiteralish(p.initializer)) continue;
            if (SENSITIVE_LOG_KEY.test(name) && !/^(body|headers)$/.test(name) && !USAGE_COUNT.test(name)) offenders.push(name);
            else if (/^(body|headers)$/.test(name) && RAW_REQ_TAINT.test(value)) offenders.push(`${name}: ${value}`);
            else if (/^(req|request)\.(body|headers)$/.test(value)) offenders.push(`${name}: ${value}`);
          } else if (ts.isSpreadAssignment(p) && /^(req|request)\.(body|headers)$/.test(text(p.expression, file))) {
            offenders.push(`...${text(p.expression, file)}`);
          }
        }
      } else if (ts.isTemplateExpression(arg)) {
        for (const span of arg.templateSpans) if (SENSITIVE_IDENTIFIER.test(text(span.expression, file))) offenders.push(text(span.expression, file));
      } else if (ts.isBinaryExpression(arg) && arg.operatorToken.kind === ts.SyntaxKind.PlusToken) {
        if (SENSITIVE_IDENTIFIER.test(text(arg, file).replace(/'[^']*'|"[^"]*"/g, ''))) offenders.push(text(arg, file).slice(0, 60));
      } else if (ts.isIdentifier(arg) || ts.isPropertyAccessExpression(arg)) {
        const t = text(arg, file);
        if (/^(req|request)\.(body|headers)$/.test(t) || (SENSITIVE_IDENTIFIER.test(t) && !/^req$/.test(t))) offenders.push(t);
      }
    }
    if (offenders.length > 0) report(node, { evidence: `${calleeName(node) ?? 'log call'} includes ${offenders.join(', ')}` });
  },
});

export const consoleLog = defineRule({
  id: 'sast.console-log',
  title: 'console.log is used instead of the structured logger',
  severity: 'low',
  confidence: 'high',
  cwe: ['CWE-532'],
  asvs: ['V16.2.4'],
  sbd: ['MT-01'],
  exploitability: 'theoretical',
  description: 'Server code writes to the console instead of using the pino logger.',
  impact: 'Console output has no timestamp, request id or redaction, so it is hard to investigate and easy to leak secrets into.',
  fix: 'Use logger.info()/logger.warn() from src/lib/logger.ts, or emit() for security events.',
  appliesTo: ['ts'],
  visit(node, file, report) {
    if (!ts.isCallExpression(node)) return;
    if (file.isTest || file.isScript || file.isPublic || file.relPath.startsWith('scripts/')) return;
    const name = calleeName(node) ?? '';
    if (/^console\.(log|info|warn|error|debug|trace|dir|table)$/.test(name)) report(node);
  },
});

export const todoSecurity = defineRule({
  id: 'sast.todo-security',
  title: 'A security-related TODO is left in the code',
  severity: 'info',
  confidence: 'high',
  cwe: ['CWE-1059'],
  asvs: [],
  sbd: ['MT-03'],
  exploitability: 'theoretical',
  description: 'A comment marked TODO/FIXME mentions authentication, authorization, validation or another security topic.',
  impact: 'It usually marks a protection that was planned but never finished.',
  fix: 'Finish the work the comment describes, or remove the comment if it is done.',
  appliesTo: ['ts', 'ejs'],
  checkFile(file, report) {
    const scanner = ts.createScanner(ts.ScriptTarget.Latest, false, ts.LanguageVariant.Standard, file.text);
    let token = scanner.scan();
    while (token !== ts.SyntaxKind.EndOfFileToken) {
      if (token === ts.SyntaxKind.SingleLineCommentTrivia || token === ts.SyntaxKind.MultiLineCommentTrivia) {
        const comment = scanner.getTokenText();
        if (TODO.test(comment) && SECURITY_WORDS.test(comment)) {
          const { line, character } = file.sf.getLineAndCharacterOfPosition(scanner.getTokenStart());
          report({ line: line + 1, column: character + 1 }, { snippet: comment.replace(/\s+/g, ' ').trim().slice(0, 200), evidence: comment.replace(/\s+/g, ' ').trim().slice(0, 200) });
        }
      }
      token = scanner.scan();
    }
  },
  checkEjs(file, report) {
    for (const hit of ejsSecurityTodos(file)) report({ line: hit.line, column: hit.column }, { snippet: hit.snippet, evidence: hit.snippet });
  },
});

export const loggingRules = [logSensitiveField, consoleLog, todoSecurity];
