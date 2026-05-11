/**
 * To ensure the users table supports email login, bcrypt passwords, and public display names.
 * Existing rows are preserved and missing columns/indexes are added repeatably.
 */
const path = require('path');
const dotenv = require('dotenv');
const { Pool } = require('pg');

// To load the database connection string from the same app environment file.
dotenv.config({ path: path.join(__dirname, '..', 'app', '.env') });

const dbConnectionString = process.env.DATABASE_URL;

// To stop before connecting if local database configuration is missing.
if (!dbConnectionString) {
    console.error('Missing DATABASE_URL in app/.env.');
    process.exitCode = 1;
    return;
}

const pool = new Pool({
    connectionString: dbConnectionString,
    ssl: {
        rejectUnauthorized: false
    }
});

const DISPLAY_NAME_PATTERN = /^[A-Za-z0-9_]{3,20}$/;

// To keep the migration safe for partially-upgraded databases.
async function tableExists(client, tableName) {
    const result = await client.query(
        `SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = $1
        ) AS exists`,
        [tableName]
    );
    return result.rows[0].exists === true;
}

async function getColumnNames(client, tableName) {
    const result = await client.query(
        `SELECT column_name
         FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = $1`,
        [tableName]
    );
    return new Set(result.rows.map((row) => row.column_name));
}

// To create or upgrade the users table without dropping existing account data.
async function ensureUsersTable() {
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        if (!await tableExists(client, 'users')) {
            await client.query(`
                CREATE TABLE users (
                    username TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    password TEXT NOT NULL
                )
            `);
            await client.query('CREATE UNIQUE INDEX users_display_name_unique_idx ON users (LOWER(display_name))');
            await client.query('COMMIT');
            console.log('Created users table for email sign-up with display names.');
            return;
        }

        const columns = await getColumnNames(client, 'users');

        // To add any missing columns while preserving existing rows and password values.
        if (!columns.has('username')) {
            await client.query('ALTER TABLE users ADD COLUMN username TEXT');
            console.log('Added missing users.username column.');
        }

        if (!columns.has('password')) {
            await client.query('ALTER TABLE users ADD COLUMN password TEXT');
            console.log('Added missing users.password column.');
        } else {
            await client.query('ALTER TABLE users ALTER COLUMN password TYPE TEXT');
        }

        if (!columns.has('display_name')) {
            await client.query('ALTER TABLE users ADD COLUMN display_name TEXT');
            console.log('Added missing users.display_name column.');
        }

        await backfillDisplayNames(client);

        // To apply NOT NULL only when current data already satisfies the constraint.
        const nullUsernameCount = await client.query('SELECT COUNT(*) AS count FROM users WHERE username IS NULL');
        const nullPasswordCount = await client.query('SELECT COUNT(*) AS count FROM users WHERE password IS NULL');
        const nullDisplayNameCount = await client.query('SELECT COUNT(*) AS count FROM users WHERE display_name IS NULL');

        if (Number(nullUsernameCount.rows[0].count) === 0) {
            await client.query('ALTER TABLE users ALTER COLUMN username SET NOT NULL');
        } else {
            console.log('users.username has null rows, so NOT NULL was not applied.');
        }

        if (Number(nullPasswordCount.rows[0].count) === 0) {
            await client.query('ALTER TABLE users ALTER COLUMN password SET NOT NULL');
        } else {
            console.log('users.password has null rows, so NOT NULL was not applied.');
        }

        if (Number(nullDisplayNameCount.rows[0].count) === 0) {
            await client.query('ALTER TABLE users ALTER COLUMN display_name SET NOT NULL');
        } else {
            console.log('users.display_name has null rows, so NOT NULL was not applied.');
        }

        // To avoid creating a uniqueness constraint if legacy duplicate usernames still exist.
        const duplicateResult = await client.query(`
            SELECT COUNT(*) AS duplicate_groups
            FROM (
                SELECT username
                FROM users
                WHERE username IS NOT NULL
                GROUP BY username
                HAVING COUNT(*) > 1
            ) duplicates
        `);

        if (Number(duplicateResult.rows[0].duplicate_groups) === 0) {
            await client.query('CREATE UNIQUE INDEX IF NOT EXISTS users_username_unique_idx ON users (username)');
            console.log('Ensured users.username is unique.');
        } else {
            console.log('Skipped unique index because duplicate usernames already exist.');
        }

        // To ensure the display_name column is unique case-insensitively.
        await client.query('CREATE UNIQUE INDEX IF NOT EXISTS users_display_name_unique_idx ON users (LOWER(display_name))');
        console.log('Ensured users.display_name is unique case-insensitively.');

        await client.query('COMMIT');
        console.log('Users table migration complete.');
    } catch (error) {
        await client.query('ROLLBACK');
        throw error;
    } finally {
        client.release();
        await pool.end();
    }
}

// To derive a valid public display name from existing data when none is already valid.
function deriveDisplayName(identifier, existingDisplayName) {
    const current = String(existingDisplayName || '').trim();
    if (DISPLAY_NAME_PATTERN.test(current)) {
        return current;
    }

    const rawIdentifier = String(identifier || '').trim();
    const localPart = rawIdentifier.includes('@') ? rawIdentifier.split('@')[0] : rawIdentifier;
    const safeBase = localPart.replace(/[^A-Za-z0-9_]/g, '_').replace(/^_+|_+$/g, '');

    if (safeBase.length >= 3) {
        return safeBase.slice(0, 20);
    }

    return `user_${safeBase || 'acct'}`.slice(0, 20);
}

// To add a numeric suffix when derived display names would otherwise collide.
function makeUniqueDisplayName(baseName, usedNames) {
    let candidate = baseName.slice(0, 20);
    let suffix = 2;

    while (usedNames.has(candidate.toLowerCase())) {
        const suffixText = `_${suffix}`;
        candidate = `${baseName.slice(0, 20 - suffixText.length)}${suffixText}`;
        suffix += 1;
    }

    usedNames.add(candidate.toLowerCase());
    return candidate;
}

// To backfill missing or invalid display names before enforcing the display-name index.
async function backfillDisplayNames(client) {
    const usersResult = await client.query(`
        SELECT username, display_name
        FROM users
        ORDER BY username
    `);
    const usedNames = new Set();
    let updatedCount = 0;

    for (const row of usersResult.rows) {
        const baseName = deriveDisplayName(row.username, row.display_name);
        const displayName = makeUniqueDisplayName(baseName, usedNames);

        if (displayName !== row.display_name) {
            await client.query(
                'UPDATE users SET display_name = $1 WHERE username = $2',
                [displayName, row.username]
            );
            updatedCount += 1;
        }
    }

    console.log(`Backfilled/normalised display names: ${updatedCount}.`);
}

ensureUsersTable().catch((error) => {
    console.error('Users migration failed:', error.message);
    process.exitCode = 1;
});
