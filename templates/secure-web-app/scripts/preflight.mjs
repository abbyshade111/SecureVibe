// Runs before `npm start` and `npm run setup`: checks the Node.js version and explains what to do if it is too old.
// Plain JavaScript on purpose so it runs on any Node.js version.
const REQUIRED = [22, 13, 0];

const current = process.versions.node.split('.').map((n) => Number(n));
const tooOld =
  current[0] < REQUIRED[0] ||
  (current[0] === REQUIRED[0] && current[1] < REQUIRED[1]) ||
  (current[0] === REQUIRED[0] && current[1] === REQUIRED[1] && current[2] < REQUIRED[2]);

if (tooOld) {
  process.stderr.write(
    [
      '',
      `This app needs Node.js ${REQUIRED.join('.')} or newer, but you have ${process.versions.node}.`,
      '',
      'How to fix it:',
      '  1. Go to https://nodejs.org/ and download the current LTS version.',
      '  2. Install it, close and reopen your terminal window.',
      '  3. Check with:  node --version',
      '  4. Run this command again.',
      '',
    ].join('\n'),
  );
  process.exit(1);
}

if (typeof process.getBuiltinModule !== 'function' || !process.getBuiltinModule('node:sqlite')) {
  process.stderr.write('\nThis Node.js build does not include the built-in SQLite database module. Please install the official Node.js release from https://nodejs.org/.\n\n');
  process.exit(1);
}
