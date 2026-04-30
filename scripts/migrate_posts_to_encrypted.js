const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const {
    encryptForDatabase,
    isEncryptedValue
} = require('../app/security/databaseEncryption');

dotenv.config({ path: path.join(__dirname, '..', 'app', '.env') });

const dbConnectionString = process.env.DATABASE_URL;
const postsJsonPath = path.join(__dirname, '..', 'app', 'public', 'json', 'posts.json');

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

async function ensurePostsTable(client) {
    await client.query(`
        CREATE TABLE IF NOT EXISTS posts (
            post_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at_display TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL
        )
    `);
}

function loadJsonPosts() {
    if (!fs.existsSync(postsJsonPath)) {
        return [];
    }

    return JSON.parse(fs.readFileSync(postsJsonPath, 'utf8'));
}

async function migratePosts() {
    const client = await pool.connect();
    let encryptedExistingCount = 0;
    let skippedEncryptedCount = 0;
    let importedJsonCount = 0;
    let skippedJsonCount = 0;

    try {
        await client.query('BEGIN');
        await ensurePostsTable(client);

        const existingResult = await client.query('SELECT post_id, content FROM posts FOR UPDATE');
        const existingPostIds = new Set();

        for (const row of existingResult.rows) {
            existingPostIds.add(row.post_id);

            if (isEncryptedValue(row.content)) {
                skippedEncryptedCount += 1;
                continue;
            }

            const encryptedContent = encryptForDatabase(row.content || '');
            await client.query(
                'UPDATE posts SET content = $1 WHERE post_id = $2',
                [encryptedContent, row.post_id]
            );
            encryptedExistingCount += 1;
        }

        for (const post of loadJsonPosts()) {
            const postId = String(post.postId);

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
