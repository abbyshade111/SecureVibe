/**
 * The helper that stops an owner's label from breaking the app built for them.
 *
 * Each case is a value a person could plausibly type, or one that defeats a weaker escape. The test does not
 * inspect the escaping: it evaluates the emitted literal and checks the value survives the round trip,
 * because what matters is that generated code parses and still says what it was meant to say.
 */
import { describe, expect, it } from 'vitest';
import { jsString } from '../../src/generator/recipes/js-literal.js';

const LINE_SEPARATOR = String.fromCharCode(0x2028);
const PARAGRAPH_SEPARATOR = String.fromCharCode(0x2029);

const ROUND_TRIP: [string, string][] = [
  ['a plain label', 'Habit'],
  ['an apostrophe, which is ordinary English', "Client's habit"],
  ['a trailing backslash, which defeats escaping only the quote', 'Backslash\\'],
  ['a backslash before a quote', "a\\'b"],
  ['a double quote', 'The "big" one'],
  ['a newline', 'two\nlines'],
  ['a carriage return', 'two\r\nlines'],
  ['a line separator JSON allows raw', `before${LINE_SEPARATOR}after`],
  ['a paragraph separator', `before${PARAGRAPH_SEPARATOR}after`],
  ['something that looks like markup', '</script><script>alert(1)</script>'],
  ['an attempt to close the literal and run code', "x'); process.exit(1); ('"],
  ['a tab', 'a\tb'],
];

describe('jsString', () => {
  for (const [what, value] of ROUND_TRIP) {
    it(`survives ${what}`, () => {
      // Evaluating the emitted literal is the whole point: if it does not parse, this throws.
      const evaluated = new Function(`return ${jsString(value)};`)() as string;
      expect(evaluated).toBe(value);
    });
  }

  it('never leaves a quote or a separator that could end the literal early', () => {
    for (const [, value] of ROUND_TRIP) {
      const inside = jsString(value).slice(1, -1);
      expect(inside).not.toMatch(/(?<!\\)"/);
      expect(inside).not.toMatch(/[\n\r]/);
      expect(inside).not.toContain(LINE_SEPARATOR);
      expect(inside).not.toContain(PARAGRAPH_SEPARATOR);
      expect(inside).not.toContain('<');
    }
  });

  it('is safe inside a script block, where a raw closing tag would end it', () => {
    const literal = jsString('</script>');
    expect(literal).not.toContain('</script>');
    expect(new Function(`return ${literal};`)()).toBe('</script>');
  });
});
