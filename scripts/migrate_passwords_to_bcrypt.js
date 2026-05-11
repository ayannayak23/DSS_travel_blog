/**
 * To migrates existing user passwords from plaintext values to bcrypt hashes.
 * The script is safe to rerun because already-hashed rows are detected and skipped.
 */
const path = require('path');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const {
    hashPassword,
    looksLikeBcryptHash
} = require('../app/security/passwordHashing');

// To load the same database connection settings used by the Express app.
dotenv.config({ path: path.join(__dirname, '..', 'app', '.env') });

const dbConnectionString = process.env.DATABASE_URL;

// To fail early if the local environment has not been configured.
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

// To walk every user row and replace only plaintext password values with bcrypt hashes.
async function migratePasswords() {
    let migratedCount = 0;
    let skippedCount = 0;

    try {
        // To use a stable order so migration output is predictable during demos.
        const userResult = await pool.query(
            'SELECT username, password FROM users ORDER BY username'
        );

        for (const user of userResult.rows) {
            const username = user.username;
            const currentPasswordValue = user.password;

            // To leave already-migrated rows unchanged so the script is safe to rerun.
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

        // To report counts without printing any password material.
        console.log(`Password migration complete. Migrated: ${migratedCount}. Skipped: ${skippedCount}.`);
    } finally {
        await pool.end();
    }
}

migratePasswords().catch((error) => {
    console.error('Password migration failed:', error.message);
    process.exitCode = 1;
});
