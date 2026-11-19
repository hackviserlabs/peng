import { createApp } from './app.js';

const {
  PORT = '3000',
  DEPLOY_MODE = 'organization',
  BIND_HOST = DEPLOY_MODE === 'local' ? '127.0.0.1' : '0.0.0.0',
  DATABASE_PATH = './data/peng.sqlite3',
  COOKIE_SECURE = 'true',
  ADMIN_USERNAME,
  ADMIN_PASSWORD,
  APP_ORIGIN,
} = process.env;

if (!/^\d+$/.test(PORT) || Number(PORT) > 65_535) throw new Error('PORT must be between 0 and 65535');
if (!['true', 'false'].includes(COOKIE_SECURE)) throw new Error('COOKIE_SECURE must be true or false');
if (!DATABASE_PATH) throw new Error('DATABASE_PATH must be nonempty');

process.umask(0o077);
const backend = createApp({
  mode: DEPLOY_MODE,
  databasePath: DATABASE_PATH,
  adminUsername: ADMIN_USERNAME || undefined,
  adminPassword: ADMIN_PASSWORD || undefined,
  cookieSecure: COOKIE_SECURE === 'true',
  appOrigin: APP_ORIGIN,
});

const server = backend.app.listen(Number(PORT), BIND_HOST, () => {
  console.log(`peng server listening on port ${server.address().port}`);
});

server.once('error', async (error) => {
  await backend.close();
  console.error('Could not listen', error);
  process.exitCode = 1;
});

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.once(signal, () => {
    server.close(async (error) => {
      await backend.close();
      if (error) process.exitCode = 1;
    });
  });
}
