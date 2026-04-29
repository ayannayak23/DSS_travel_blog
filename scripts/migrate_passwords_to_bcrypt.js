const path = require('path');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const {
    hashPassword,
    looksLikeBcryptHash
} = require('../app/security/passwordHashing');

dotenv.config({ path: path.join(__dirname, '..', 'app', '.env') });

const dbConnectionString = process.env.DATABASE_URL;

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

async function migratePasswords() {
    let migratedCount = 0;
    let skippedCount = 0;

    try {
        const userResult = await pool.query(
            'SELECT username, password FROM users ORDER BY username'
        );

        for (const user of userResult.rows) {
            const username = user.username;
            const currentPasswordValue = user.password;

            // Already-migrated rows are left unchanged so the script is safe to rerun.
            if (looksLikeBcryptHash(currentPasswordValue)) {
                skippedCount += 1;
                console.log(`Skipped already-hashed password for user: ${username}`);
                continue;
            }

            if (typeof currentPasswordValue !== 'string' || currentPasswordValue.length === 0) {
                skippedCount += 1;
                console.log(`Skipped missing password value for user: ${username}`);
                continue;
            }

            const passwordHash = await hashPassword(currentPasswordValue);
            await pool.query(
                'UPDATE users SET password = $1 WHERE username = $2',
                [passwordHash, username]
            );

            migratedCount += 1;
            console.log(`Migrated password for user: ${username}`);
        }

        console.log(`Password migration complete. Migrated: ${migratedCount}. Skipped: ${skippedCount}.`);
    } finally {
        await pool.end();
    }
}

migratePasswords().catch((error) => {
    console.error('Password migration failed:', error.message);
    process.exitCode = 1;
});
