/**
 * To migrates post content into PostgreSQL with server-side database encryption.
 * Existing encrypted rows and already-imported JSON posts are skipped so the script is repeatable.
 */
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const {
    encryptForDatabase,
    isEncryptedValue
} = require('../../security/databaseEncryption');

// To load DATABASE_URL and DATABASE_ENCRYPTION_KEY from the app environment.
dotenv.config({ path: path.join(__dirname, '..', '..', '.env') });

const dbConnectionString = process.env.DATABASE_URL;
const postsJsonPath = path.join(__dirname, '..', 'json', 'posts.json');

// To stop before connecting if the database URL is missing.
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

// To ensure the posts table exists before importing JSON data or encrypting rows.
async function ensurePostsTable(client) {
    await client.query(`
        CREATE TABLE IF NOT EXISTS posts (
            post_id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            created_at_display TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL
        )
    `);
}

// To load legacy JSON posts when the original seed file is still present.
function loadJsonPosts() {
    if (!fs.existsSync(postsJsonPath)) {
        return [];
    }

    return JSON.parse(fs.readFileSync(postsJsonPath, 'utf8'));
}

// To encrypt existing database rows and import any missing legacy JSON posts in one transaction.
async function migratePosts() {
    const client = await pool.connect();
    let encryptedExistingCount = 0;
    let skippedEncryptedCount = 0;
    let importedJsonCount = 0;
    let skippedJsonCount = 0;

    try {
        await client.query('BEGIN');
        await ensurePostsTable(client);

        // To lock existing rows while checking whether each post still needs encryption.
        const existingResult = await client.query('SELECT post_id, content FROM posts FOR UPDATE');
        const existingPostIds = new Set();

        for (const row of existingResult.rows) {
            const postId = Number(row.post_id);
            if (!Number.isFinite(postId)) {
                continue;
            }

            existingPostIds.add(postId);

            if (isEncryptedValue(row.content)) {
                skippedEncryptedCount += 1;
                continue;
            }

            const encryptedContent = encryptForDatabase(row.content || '');
            await client.query(
                'UPDATE posts SET content = $1 WHERE post_id = $2',
                [encryptedContent, postId]
            );
            encryptedExistingCount += 1;
        }

        // To import only JSON posts whose IDs are not already present in PostgreSQL.
        for (const post of loadJsonPosts()) {
            const postId = Number.parseInt(String(post.postId), 10);

            if (!Number.isFinite(postId)) {
                skippedJsonCount += 1;
                continue;
            }

            if (existingPostIds.has(postId)) {
                skippedJsonCount += 1;
                continue;
            }

            await client.query(
                `INSERT INTO posts (post_id, username, created_at_display, title, content)
                 VALUES ($1, $2, $3, $4, $5)`,
                [
                    postId,
                    String(post.username || ''),
                    String(post.timestamp || ''),
                    String(post.title || ''),
                    encryptForDatabase(String(post.content || ''))
                ]
            );
            existingPostIds.add(postId);
            importedJsonCount += 1;
        }

        await client.query('COMMIT');
        console.log(`Post encryption migration complete. Existing encrypted: ${encryptedExistingCount}. Already encrypted skipped: ${skippedEncryptedCount}. JSON imported: ${importedJsonCount}. JSON skipped: ${skippedJsonCount}.`);
    } catch (error) {
        // To roll back partial changes so a failed migration can be fixed and rerun cleanly.
        await client.query('ROLLBACK');
        throw error;
    } finally {
        client.release();
        await pool.end();
    }
}

migratePosts().catch((error) => {
    console.error('Post encryption migration failed:', error.message);
    process.exitCode = 1;
});
