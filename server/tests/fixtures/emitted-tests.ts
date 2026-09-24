/**
 * Finding a named test inside a file a recipe emitted.
 *
 * The obvious check is `source.includes("test('" + name + "'")`, and it was the check here until the emitter
 * started writing names as JSON literals so that a label like "Client's habit" could not break the file. A
 * check that hard-codes the quoting has to be edited every time the emitter changes, and — worse — it passes
 * or fails for reasons that have nothing to do with whether the test is there.
 *
 * So this reads whatever literal follows `test(` and evaluates it, then compares the value. It is agnostic
 * about quoting and about escaping, which is the point: it asks the question the caller actually has.
 */

const TEST_CALL = /\b(?:it|test)\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)/g;

/** Every test name the source declares, with its escaping resolved. */
export function emittedTestNames(source: string): string[] {
  const names: string[] = [];
  for (const match of source.matchAll(TEST_CALL)) {
    const literal = match[1]!;
    try {
      // Our own generated sources, read in a test: evaluating the literal is how the escaping gets resolved.
      names.push(new Function(`return ${literal};`)() as string);
    } catch {
      // A literal that does not evaluate is a real problem, but it is not this helper's to report: it shows
      // up as the name simply not being found, and as the generated app failing to compile.
    }
  }
  return names;
}

/** Whether `source` declares a test called exactly `name`. */
export function emitsTestNamed(source: string, name: string): boolean {
  return emittedTestNames(source).includes(name);
}
