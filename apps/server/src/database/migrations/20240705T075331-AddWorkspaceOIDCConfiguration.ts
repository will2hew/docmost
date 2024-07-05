import { sql, type Kysely } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`
        ALTER TABLE workspaces
        ADD COLUMN "oidcClientId" TEXT,
        ADD COLUMN "oidcClientSecret" TEXT,
        ADD COLUMN "oidcIssuerUrl" TEXT,
        ADD COLUMN "oidcJITEnabled" BOOLEAN DEFAULT FALSE,
        ADD COLUMN "oidcDomains" TEXT[] DEFAULT '{}'
    `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`
        ALTER TABLE workspaces
        DROP COLUMN "oidcClientId",
        DROP COLUMN "oidcClientSecret",
        DROP COLUMN "oidcIssuerUrl",
        DROP COLUMN "oidcJITEnabled",
        DROP COLUMN "oidcDomains"
    `.execute(db);
}
