import { sql, type Kysely } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`ALTER TABLE workspaces RENAME COLUMN email_domains TO approved_domains`.execute(
    db,
  );
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`ALTER TABLE workspaces RENAME COLUMN approved_domains TO email_domains`.execute(
    db,
  );
}
