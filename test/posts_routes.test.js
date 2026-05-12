const assert = require('assert');
const { registerPostRoutes } = require('../app/server/posts');
const { PATHS } = require('../app/server/config');
const { decryptFromDatabase } = require('../app/security/databaseEncryption');

const TEST_KEY = 'd8dacde546e09c4c9963a97d99777c8c4ee81f94a28e854a0281d9608a96426a';
const originalKey = process.env.DATABASE_ENCRYPTION_KEY;

// To create a test context with a mock database and route handlers, and to reset the encryption key after tests.
// This allows testing the post creation, editing, and deletion routes without needing a real database or server.
function createTestContext() {
    process.env.DATABASE_ENCRYPTION_KEY = TEST_KEY;

    const handlers = new Map();
    const pool = {
        calls: [],
        async query(sql, params = []) {
            this.calls.push({ sql, params });

            if (sql.includes('MAX(post_id)')) {
                return { rows: [{ max_id: 7 }] };
            }

            if (sql.includes('COUNT(*) AS count')) {
                return { rows: [{ count: 0 }] };
            }

            return { rows: [], rowCount: 1 };
        }
    };

    registerPostRoutes(
        {
            get() {},
            post(path, ...routeHandlers) {
                handlers.set(path, routeHandlers.at(-1));
            }
        },
        {
            pool,
            validateSession(req, res, next) {
                next();
            },
            validateCsrfToken(req, res, next) {
                next();
            }
        }
    );

    return {
        pool,
        async post(path, req) {
            const res = {
                sentFile: null,
                status(code) {
                    this.statusCode = code;
                    return this;
                },
                send(body) {
                    this.body = body;
                    return this;
                },
                sendFile(filePath, callback) {
                    this.sentFile = filePath;
                    callback?.(null);
                    return this;
                }
            };

            await handlers.get(path)(req, res);
            return res;
        }
    };
}

// Tests for the post routes, including creating a new post, editing an existing post, and deleting a post. 
describe('post routes', function () {
    after(function () {
        if (typeof originalKey === 'string') {
            process.env.DATABASE_ENCRYPTION_KEY = originalKey;
        } else {
            delete process.env.DATABASE_ENCRYPTION_KEY;
        }
    });

    it('creates a new post', async function () {
        const { pool, post } = createTestContext();
        const res = await post('/makepost', {
            body: { postId: '', title_field: 'First trip', content_field: 'Packing list and notes' },
            files: [],
            currentUser: 'ayan@example.com'
        });

        assert.strictEqual(res.sentFile, PATHS.myPostsPage);
        assert.strictEqual(pool.calls[0].sql.includes('MAX(post_id)'), true);
        assert.deepStrictEqual(pool.calls[1].params, [8]);
        assert.deepStrictEqual(pool.calls[2].params.slice(0, 4), [8, 'ayan@example.com', pool.calls[2].params[2], 'First trip']);
        assert.strictEqual(decryptFromDatabase(pool.calls[2].params[4]), 'Packing list and notes');
    });

    it('edits an existing post', async function () {
        const { pool, post } = createTestContext();
        const res = await post('/makepost', {
            body: { postId: '8', title_field: 'Updated trip', content_field: 'Updated <b>content</b>' },
            files: [],
            currentUser: 'ayan@example.com'
        });

        assert.strictEqual(res.sentFile, PATHS.myPostsPage);
        assert.strictEqual(pool.calls.some((call) => call.sql.includes('MAX(post_id)')), false);
        assert.deepStrictEqual(pool.calls[0].params, [8]);
        assert.strictEqual(decryptFromDatabase(pool.calls[1].params[4]), 'Updated &lt;b&gt;content&lt;/b&gt;');
    });

    it('deletes a post', async function () {
        const { pool, post } = createTestContext();
        const res = await post('/deletepost', { body: { postId: '8' } });

        assert.strictEqual(res.sentFile, PATHS.myPostsPage);
        assert.strictEqual(pool.calls[0].sql, 'DELETE FROM posts WHERE post_id = $1');
        assert.deepStrictEqual(pool.calls[0].params, [8]);
    });
});
