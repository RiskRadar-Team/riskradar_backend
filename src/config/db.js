import { Pool } from "pg";

import pg from "pg";
const { types } = pg;
// OID 1082 = DATE
types.setTypeParser(1082, (value) => value);
//to fix 2026-06-25T18:30:00.000Z to 2026-06-25

//create a connection pool to the database
export const dbPool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

//table creation if not exist
export async function initialiseDatabaseTable() {
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      full_name VARCHAR(150) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      role VARCHAR(20)
        DEFAULT 'USER'
        CHECK (role IN ('USER','ADMIN')),
      email_verified BOOLEAN DEFAULT FALSE,
      is_active BOOLEAN DEFAULT TRUE,
      last_login TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,
      token TEXT NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS domains(
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      domain_name VARCHAR(255) NOT NULL UNIQUE,
      list_type VARCHAR(20)
        NOT NULL
        CHECK (list_type IN ('BLACKLIST', 'WHITELIST')),
      threat_type VARCHAR(100),
      reason TEXT,
      source VARCHAR(100),
      confidence_score SMALLINT
        CHECK (confidence_score BETWEEN 0 AND 100),
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_by UUID
        REFERENCES users(id)
        ON DELETE SET NULL,
      updated_by UUID
        REFERENCES users(id)
        ON DELETE SET NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_domains_name
      ON domains(domain_name);
      CREATE INDEX IF NOT EXISTS idx_domains_list_type
      ON domains(list_type);
      CREATE INDEX IF NOT EXISTS idx_domains_active
      ON domains(is_active);
  `);
  console.log("Database tables initialized successfully");
}
