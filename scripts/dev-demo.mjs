import { spawn } from 'node:child_process';
import net from 'node:net';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const pnpm = process.env.npm_execpath;
if (!pnpm) throw new Error('Run this launcher with pnpm demo.');
const reuseIssuer = process.argv.includes('--reuse-issuer');
if (reuseIssuer) {
  const response = await fetch('http://localhost:3005/.well-known/openid-credential-issuer');
  const metadata = await response.json();
  if (!response.ok || metadata.credential_issuer !== 'http://localhost:3005') {
    throw new Error('The existing service on 3005 is not the expected local mock issuer.');
  }
}
const ports = [3104, 5185, 5184, ...(reuseIssuer ? [] : [3005])];
// Do not reuse or terminate an unrelated wallet/service, or silently change ports.
for (const port of ports) {
  await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', () =>
      reject(new Error(`Port ${port} is occupied. Stop its owner before starting this demo.`))
    );
    server.listen(port, 'localhost', () => server.close(resolve));
  });
}
const env = {
  ...process.env,
  PORT: '',
  VERIFIER_PORT: '3104',
  VERIFIER_BASE_URL: 'http://localhost:3104',
  VERIFIER_BACKEND_URL: 'http://localhost:3104',
  VITE_BACKEND_URL: 'http://localhost:3104',
  WALLET_BASE_URL: 'http://localhost:5184',
  VITE_WALLET_URL: 'http://localhost:5184',
  VITE_VERIFIER_URL: 'http://localhost:3104/present',
  VITE_ISSUER_URL: 'http://localhost:3005',
  ISSUER_BASE_URL: 'http://localhost:3005',
  ISSUER_DID: 'did:web:localhost%3A3005',
  ASKMI_TSL_URL: 'http://localhost:3005/v1/eudi-lotl.json',
  ASKMI_TEST_MODE: '0',
  MITCH_TEST_MODE: '0',
  CORS_ALLOWED_ORIGINS: 'http://localhost:5184,http://localhost:5185',
};
const commands = [
  ...(!reuseIssuer ? [['--filter', '@askmi/issuer-mock', 'dev']] : []),
  ['--filter', 'verifier-backend', 'dev'],
  ['--dir', 'src/apps/verifier-demo/frontend', 'dev', '--port', '5185', '--strictPort'],
  ['--filter', '@askmi/wallet-pwa', 'dev:demo'],
];
const children = [];
let stopping = false;
function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  for (const child of children) {
    if (process.platform === 'win32') {
      spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], {
        windowsHide: true,
        stdio: 'ignore',
      });
    } else {
      try {
        process.kill(-child.pid, 'SIGTERM');
      } catch {
        /* already exited */
      }
    }
  }
  process.exitCode = code;
}
for (const args of commands) {
  const nativePnpm = pnpm.endsWith('.exe');
  const child = spawn(nativePnpm ? pnpm : process.execPath, nativePnpm ? args : [pnpm, ...args], {
    cwd: root,
    env,
    stdio: 'inherit',
    windowsHide: true,
    detached: process.platform !== 'win32',
  });
  children.push(child);
  child.on('error', (error) => {
    console.error(error);
    stop(1);
  });
  child.on('exit', (code) => {
    if (!stopping) stop(code || 1);
  });
}
process.on('SIGINT', () => stop());
process.on('SIGTERM', () => stop());
console.log('Demo starting. Store: http://localhost:5185/?flow=connect');
console.log(
  'Isolated demo wallet: http://localhost:5184 (test credentials only). Existing port 5174 is untouched.'
);
