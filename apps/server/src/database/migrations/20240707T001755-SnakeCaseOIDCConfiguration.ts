import { sql, type Kysely } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`ALTER TABLE workspaces RENAME COLUMN "oidcEnabled" TO oidc_enabled`.execute(
    db,
  );
  await sql`ALTER TABLE workspaces RENAME COLUMN "oidcClientId" TO oidc_client_id`.execute(
    db,
  );
  await sql`ALTER TABLE workspaces RENAME COLUMN "oidcClientSecret" TO oidc_client_secret`.execute(
    db,
  );
  await sql`ALTER TABLE workspaces RENAME COLUMN "oidcIssuerUrl" TO oidc_issuer_url`.execute(
    db,
  );
  await sql`ALTER TABLE workspaces RENAME COLUMN "oidcJITEnabled" TO oidc_jit_enabled`.execute(
    db,
  );
  await sql`ALTER TABLE workspaces RENAME COLUMN "oidcButtonName" TO oidc_button_name`.execute(
    db,
  );
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`ALTER TABLE workspaces RENAME COLUMN oidc_enabled TO "oidcEnabled"`.execute(
    db,
  );
  await sql`ALTER TABLE workspaces RENAME COLUMN oidc_client_id TO "oidcClientId"`.execute(
    db,
  );
  await sql`ALTER TABLE workspaces RENAME COLUMN oidc_client_secret TO "oidcClientSecret"`.execute(
    db,
  );
  await sql`ALTER TABLE workspaces RENAME COLUMN oidc_issuer_url TO "oidcIssuerUrl"`.execute(
    db,
  );
  await sql`ALTER TABLE workspaces RENAME COLUMN oidc_jit_enabled TO "oidcJITEnabled"`.execute(
    db,
  );
  await sql`ALTER TABLE workspaces RENAME COLUMN oidc_button_name TO "oidcButtonName"`.execute(
    db,
  );
}
