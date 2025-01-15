import Database from 'better-sqlite3';

const db = new Database('backend.db', { verbose: console.log });

interface Token {
    id: string;
    created_at: number;
    expires_at: number;
    banned: boolean;
    fid: number;
  }

db.exec(`
  CREATE TABLE IF NOT EXISTS tokens (
    id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at INTEGER NOT NULL,
    banned BOOLEAN NOT NULL DEFAULT FALSE,
    fid INTEGER NOT NULL
  )
`);

export function insertToken(id: string, expiresAt: number, banned: boolean, fid: number) {
    const stmt = db.prepare(`
    INSERT INTO tokens (id, expires_at, banned, fid)
    VALUES (?, ?, ?, ?)
  `);
    stmt.run(id, expiresAt, banned ? 1 : 0, fid);
}

export function getToken(id: string) {
    const stmt = db.prepare(`
    SELECT * FROM tokens WHERE id = ?
  `);
    return stmt.get(id) as Token | undefined;
}

export function getLatestTokenByFid(fid: number) {
    const currentTime = Math.floor(Date.now() / 1000);
    const stmt = db.prepare(`
      SELECT * FROM tokens
      WHERE fid = ? AND expires_at > ? AND banned = FALSE
      ORDER BY created_at DESC
      LIMIT 1
    `);
    return stmt.get(fid, currentTime) as Token | undefined;
}