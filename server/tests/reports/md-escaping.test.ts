/**
 * Report tables must survive the text that goes into them.
 *
 * Every cell in a compliance or security report can carry text nobody on this project wrote: a
 * file name from the app being checked, a finding title from a scanner, a sentence from an AI
 * review. A cell that breaks its own table lets that text overwrite the column beside it, and a
 * report that can be made to say something false is the one thing this project cannot ship.
 */
import { describe, expect, it } from 'vitest';
import { mdTable } from '../../src/reports/md.js';
import { markdownCells } from '../fixtures/markdown-cells.js';

describe('markdown cells', () => {
  it('keeps a pipe inside the cell it came from', () => {
    const row = mdTable(['A', 'B'], [['a|b', 'second']]).split('\n')[2]!;
    expect(markdownCells(row)).toEqual(['a\\|b', 'second']);
  });

  it('does not let a backslash before a pipe overwrite the next column', () => {
    // The case CodeQL flagged as js/incomplete-sanitization. Escaping the pipe but not the
    // backslash turns `\|` into `\\|`, which Markdown reads as an escaped backslash followed by a
    // live delimiter: the cell ends early and the attacker's text lands in the next column.
    const attack = `x\\|INJECTED|y`;
    const row = mdTable(['A', 'B'], [[attack, 'second']]).split('\n')[2]!;
    const cells = markdownCells(row);
    expect(cells).toHaveLength(2);
    expect(cells[1]).toBe('second');
    expect(cells[1]).not.toContain('INJECTED');
  });

  it('keeps a trailing backslash from swallowing the delimiter', () => {
    const row = mdTable(['A', 'B'], [['ends with a backslash\\', 'second']]).split('\n')[2]!;
    const cells = markdownCells(row);
    expect(cells).toHaveLength(2);
    expect(cells[1]).toBe('second');
  });

  it('still flattens newlines so a cell cannot start a new row', () => {
    const row = mdTable(['A', 'B'], [['one\ntwo', 'second']]).split('\n');
    expect(row).toHaveLength(3);
    expect(markdownCells(row[2]!)).toEqual(['one two', 'second']);
  });
});
