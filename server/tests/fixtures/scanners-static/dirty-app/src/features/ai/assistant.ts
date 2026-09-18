// Fixture: AI-feature rules — API key in the prompt, unescaped output, a disallowed import (CONTRACTS §3).
import { Configuration } from 'openai';

const systemPrompt = `You are a helpful assistant. Key: ${process.env.ANTHROPIC_API_KEY}`;

export function renderAnswer(aiResponse: string): string {
  return safeHtml(aiResponse);
}

declare function safeHtml(value: string): string;

export { Configuration, systemPrompt };
