/**
 * AI-feature rules: model output rendered as HTML, and the API key leaking into prompts.
 */
import ts from 'typescript';
import { calleeName, calleeTail, isStringLike, propertyName, text, type TsFile } from '../engine.js';
import { AI_NAME, assignedName, defineRule } from './base.js';

const MARKDOWN_RENDERERS = /^(marked|marked\.parse|marked\.parseInline|md\.render|md\.renderInline|markdown|markdownToHtml|renderMarkdown|remark|showdown|micromark)$/;
const API_KEY_REF = /(ANTHROPIC_API_KEY|OPENAI_API_KEY|API_KEY\b|apiKey\b|api_key\b|anthropicKey|anthropicApiKey)/;
const PROMPT_PROPERTY = /^(system|prompt|content|messages|text|instructions|input|systemPrompt|user)$/;
const PROMPT_NAME = /(prompt|system|instruction|context|message)/i;
const MODEL_CALL = /^(create|parse|stream|complete|generate|chat)$/;

export const aiOutputRenderedUnescaped = defineRule({
  id: 'sast.ai-output-rendered-unescaped',
  title: 'The AI answer is rendered as HTML',
  severity: 'high',
  confidence: 'high',
  cwe: ['CWE-79'],
  asvs: ['V1.2.1'],
  aisvs: ['C7.3.3'],
  exploitability: 'requires-auth',
  description: 'Text produced by the AI model is inserted into a page without escaping (unescaped template output, safeHtml(), a markdown-to-HTML renderer or innerHTML).',
  impact: 'The model can be steered by a user into producing script tags, which then run in another person’s browser.',
  fix: 'Render the answer as plain text (<%= answer %> or textContent). Do not convert it to HTML.',
  appliesTo: ['ts', 'ejs'],
  checkEjs(file, report) {
    for (const tag of file.doc.tags) {
      if (tag.kind === 'unescaped' && AI_NAME.test(tag.code)) {
        report({ line: tag.line, column: tag.column }, { snippet: file.text.slice(tag.start, tag.end), evidence: `Unescaped AI output <%- ${tag.code} %> at line ${tag.line}` });
      }
    }
  },
  visit(node, file, report) {
    if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
      const name = calleeName(node) ?? '';
      const arg = node.arguments?.[0];
      if (!arg) return;
      if ((name === 'SafeHtml' || name === 'safeHtml' || MARKDOWN_RENDERERS.test(name)) && AI_NAME.test(text(arg, file))) {
        report(node, { evidence: `${name}(${text(arg, file).slice(0, 60)}) turns model output into HTML` });
        return;
      }
      if (calleeTail(node) === 'insertAdjacentHTML' && node.arguments?.[1] && AI_NAME.test(text(node.arguments[1], file))) report(node);
      else if (name === 'res.send' && ts.isTemplateExpression(arg) && /</.test(arg.head.text) && arg.templateSpans.some((s) => AI_NAME.test(text(s.expression, file)))) {
        report(node, { confidence: 'medium', evidence: 'res.send() builds HTML around model output' });
      }
      return;
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isPropertyAccessExpression(node.left)) {
      const prop = node.left.name.text;
      if ((prop === 'innerHTML' || prop === 'outerHTML') && !isStringLike(node.right) && AI_NAME.test(text(node.right, file))) report(node);
    }
  },
});

function promptContext(node: ts.Node, file: TsFile): string | undefined {
  let cur: ts.Node | undefined = node.parent;
  while (cur && !ts.isSourceFile(cur)) {
    if (ts.isPropertyAssignment(cur)) {
      const name = propertyName(cur.name) ?? '';
      if (PROMPT_PROPERTY.test(name)) return `property "${name}"`;
      if (/^(apiKey|api_key|authToken|headers|authorization)$/i.test(name)) return undefined; // SDK configuration, not a prompt
    }
    if (ts.isVariableDeclaration(cur) && ts.isIdentifier(cur.name) && PROMPT_NAME.test(cur.name.text)) return `variable "${cur.name.text}"`;
    if (ts.isCallExpression(cur) && MODEL_CALL.test(calleeTail(cur) ?? '') && /messages|completions|anthropic|client|model/i.test(text(cur.expression, file))) return `${text(cur.expression, file)}()`;
    if (ts.isFunctionLike(cur) || ts.isBlock(cur)) return undefined;
    cur = cur.parent;
  }
  return undefined;
}

export const aiApiKeyInPrompt = defineRule({
  id: 'sast.ai-api-key-in-prompt',
  title: 'The AI API key is placed in the prompt',
  severity: 'critical',
  confidence: 'high',
  cwe: ['CWE-200'],
  asvs: ['V13.3.2'],
  aisvs: ['C9.5.4'],
  sbd: ['AC-05'],
  exploitability: 'requires-auth',
  description: 'The Anthropic API key (or another secret) is part of the text sent to the model as system prompt, message or context.',
  impact: 'Anyone who can make the model repeat its instructions obtains the key and can spend your budget or read your data.',
  fix: 'Pass the key only to the SDK client constructor; never include secrets or config values in prompts.',
  appliesTo: ['ts'],
  visit(node, file, report) {
    let holds = false;
    if (ts.isTemplateExpression(node)) holds = node.templateSpans.some((s) => API_KEY_REF.test(text(s.expression, file)));
    else if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) holds = API_KEY_REF.test(text(node, file).replace(/'[^']*'|"[^"]*"/g, ''));
    else if (ts.isPropertyAssignment(node) && (ts.isIdentifier(node.initializer) || ts.isPropertyAccessExpression(node.initializer))) {
      holds = API_KEY_REF.test(text(node.initializer, file)) && PROMPT_PROPERTY.test(propertyName(node.name) ?? '');
      if (holds) {
        report(node, { evidence: `${propertyName(node.name)}: ${text(node.initializer, file)}` });
        return;
      }
    }
    if (!holds) return;
    // Avoid double reports for nested template/concatenation nodes.
    if (node.parent && (ts.isTemplateExpression(node.parent) || (ts.isBinaryExpression(node.parent) && node.parent.operatorToken.kind === ts.SyntaxKind.PlusToken))) return;
    const ctx = promptContext(node, file) ?? (PROMPT_NAME.test(assignedName(node) ?? '') ? `variable "${assignedName(node)}"` : undefined);
    if (ctx) report(node, { evidence: `An API key reference is interpolated into ${ctx}` });
  },
});

export const aiRules = [aiOutputRenderedUnescaped, aiApiKeyInPrompt];
