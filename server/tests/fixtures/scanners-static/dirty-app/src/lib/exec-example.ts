// Fixture: code execution and unsafe deserialisation rules (CONTRACTS §3).
import { exec } from 'node:child_process';
import vm from 'node:vm';
import { load } from 'js-yaml';

export function runBuildScript(): void {
  exec('npm run build');
}

export function runUserCommand(req: { headers: { 'x-cmd': string } }): void {
  exec(req.headers['x-cmd']);
}

export function evaluateExpression(expr: string): unknown {
  return eval(expr);
}

export function makeAdder(): unknown {
  return new Function('a', 'b', 'return a + b');
}

export function runInSandbox(code: string): unknown {
  return vm.runInNewContext(code);
}

export function loadUserYaml(req: { headers: { 'x-yaml': string } }): unknown {
  return load(req.headers['x-yaml'], { schema: 'DEFAULT_FULL_SCHEMA' } as never);
}
