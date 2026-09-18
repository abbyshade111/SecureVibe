import tseslint from 'typescript-eslint';
import security from 'eslint-plugin-security';

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**', 'tests/fixtures/**'] },
  ...tseslint.configs.recommended,
  security.configs.recommended,
  {
    rules: {
      // Too noisy on ordinary bracket access; the SecureVibe static analyser covers injection sinks precisely.
      'security/detect-object-injection': 'off',
      // SecureVibe manages a workspace of project folders, so nearly every file operation takes a computed path.
      // Confinement is enforced centrally in store/paths.ts (realpath + prefix check) and covered by tests.
      'security/detect-non-literal-fs-filename': 'off',
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/no-explicit-any': 'warn',
    },
  },
);
