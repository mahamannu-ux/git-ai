/** Disposable IT-T20h-01 inputs. Run only inside TrackAI's it-db.sh shell. */
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

async function main(): Promise<void> {
  const trackai = process.env.TRACKAI_ROOT;
  const output = process.argv[2];
  const database = process.env.DATABASE_URL;
  if (!trackai || !output || !database || process.env.TASK6_EPHEMERAL_DATABASE !== '1') {
    throw new Error('TRACKAI_ROOT, output directory, and it-db.sh environment are required');
  }
  const url = new URL(database);
  if (!['127.0.0.1', 'localhost'].includes(url.hostname)
    || url.pathname !== '/trackai_task20h_founder') {
    throw new Error('requires the disposable local trackai_task20h_founder database');
  }
  const directory = resolve(output);
  if (existsSync(directory)) throw new Error('output directory already exists; use a new path');

  const fromTrackai = (relative: string) => import(pathToFileURL(join(trackai, relative)).href);
  const [{ trustFixture }, { db, pool }, { ssoTenants }, machineService] = await Promise.all([
    fromTrackai('apps/api/src/features/security/testing/trust-fixture.ts'),
    fromTrackai('apps/api/src/core/db/index.ts'),
    fromTrackai('apps/api/src/core/db/schema.ts'),
    fromTrackai('apps/api/src/core/security/machine-security-service.ts'),
  ]);

  const fixture = trustFixture(new Date());
  const tenantId = randomUUID();
  const repositoryId = randomUUID();
  const suffix = randomUUID();
  const actorId = 'task20h-founder-test';

  mkdirSync(directory, { mode: 0o700 });
  mkdirSync(join(directory, 'trust'), { mode: 0o700 });
  mkdirSync(join(directory, 'private'), { mode: 0o700 });
  const save = (path: string, value: string, mode = 0o600) =>
    writeFileSync(join(directory, path), value, { mode, flag: 'wx' });
  save('trust/root.json', `${JSON.stringify(fixture.rootDocument)}\n`);
  save('trust/dev-pins.json', `${JSON.stringify([fixture.root.keyid])}\n`);
  save('private/policy.pem', fixture.policy.privateKeyPem);
  save('private/lease.pem', fixture.lease.privateKeyPem);

  try {
    await db.insert(ssoTenants).values({
      id: tenantId,
      companyName: 'Task20h Founder Disposable',
      domain: `task20h-${suffix}.invalid`,
      supabaseProviderId: `task20h-${suffix}`,
    });
    const machine = await machineService.registerDeveloperMachine({
      tenantId, installationId: `task20h-${suffix}`, displayName: 'TrackAiMDMtest', actorId,
    });
    const credential = await machineService.issueMachineCredential({
      tenantId, machineId: machine.id, actorId,
    });
    save('private/credential.txt', `${credential.plaintext}\n`);
    save('private/bootstrap.json', `${JSON.stringify({
      version: 1,
      repositories: [{
        repository_url: 'https://example.invalid/task20h-founder',
        repository_id: repositoryId,
        tenant_id: tenantId,
        api_base_url: 'http://127.0.0.1:8080',
        credential_key_id: credential.keyId,
      }],
    })}\n`);
    save('tenant-id', `${tenantId}\n`);
    save('machine-id', `${machine.id}\n`);
    save('settings-monitor.json', `${JSON.stringify({
      reason: 'Task20h founder live monitor test', monitor_mode: 'monitor',
      rules: { 'secrets.agent_read_env': { enabled: true } },
    })}\n`);
    save('settings-off.json', `${JSON.stringify({
      reason: 'Task20h founder live off test', monitor_mode: 'off',
    })}\n`);
    console.log(`Disposable tenant and machine created; files saved under ${directory}`);
    console.log('Private keys and credential were written to files; their values were not printed.');
  } finally {
    await pool.end();
  }
}

main().catch((error: unknown) => {
  console.error(`founder-live-setup failed: ${(error as Error).message}`);
  process.exitCode = 1;
});
