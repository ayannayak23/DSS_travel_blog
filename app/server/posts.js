const multer = require('multer');
const { decryptFromDatabase, encryptForDatabase } = require('../security/databaseEncryption');
const { LIMITS, PATTERNS, PATHS, ALLOWED_IMAGE_MIME_TYPES } = require('./config');
const { getSafeString, isWithinMaxLength, sendPage } = require('./utils');

// Configure safe image uploads with memory storage, file size limits, and MIME type checks.
const upload = multer({
    storage: multer.memoryStorage(),
    // Limit the file size and number of files.
    limits: {
        fileSize: LIMITS.maxImageSizeBytes,
        files: LIMITS.maxImagesPerPost
    },
    // MIME type validation.
    fileFilter: (req, file, cb) => {
        if (ALLOWED_IMAGE_MIME_TYPES.has(file.mimetype)) {
            return cb(null, true);
        }

        const error = new Error('Invalid image type.');
        error.code = 'INVALID_IMAGE_TYPE';
        return cb(error);
    }
});

// Validate and parse the post ID from user input, ensuring it is a positive integer within allowed length.
function parsePostId(postId) {
    if (postId === '') {
        return null;
    }

    if (!PATTERNS.numericOnly.test(postId) || !isWithinMaxLength(postId, LIMITS.maxPostIdLength)) {
        return null;
    }

    const parsed = Number.parseInt(postId, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
        return null;
    }

    return parsed;
}

function containsHtmlLikeInput(value) {
    return PATTERNS.plainTextOnly.test(value);
}

function buildPostFromRow(row) {
    return {
        username: row.author_name || 'Unknown user',
        timestamp: row.created_at_display,
        postId: row.post_id,
        title: row.title,
        content: decryptFromDatabase(row.content)
    };
}

// Get the next available post ID by finding the current maximum and adding one.
async function getNextPostId(pool) {
    const result = await pool.query('SELECT COALESCE(MAX(post_id), 0) AS max_id FROM posts');
    return (Number(result.rows[0]?.max_id) || 0) + 1;
}

// Get the current timestamp for posts.
function getCurrentDisplayTimestamp() {
    return new Date().toLocaleString('en-GB');
}

// Register routes related to posts, including fetching, creating, and deleting posts and images.
function registerPostRoutes(app, { pool, validateSession, validateCsrfToken }) {
    // Fetch all posts with decrypted content and author display names.
    app.get('/posts-data', validateSession, async (req, res) => {
        try {
            const postsResult = await pool.query(`
                SELECT
                    posts.post_id,
                    COALESCE(
                        NULLIF(users.display_name, ''),
                        CASE
                            WHEN posts.username LIKE '%@%' THEN split_part(posts.username, '@', 1)
                            WHEN NULLIF(posts.username, '') IS NOT NULL THEN posts.username
                            ELSE 'Unknown user'
                        END
                    ) AS author_name,
                    posts.created_at_display,
                    posts.title,
                    posts.content
                FROM posts
                LEFT JOIN users ON LOWER(users.username) = LOWER(posts.username)
                ORDER BY posts.post_id
            `);

            res.json(postsResult.rows.map(buildPostFromRow));
        } catch (error) {
            console.error('Failed to load encrypted posts:', error.message);
            res.status(500).json([]);
        }
    });

    // Return uploaded image details only for authenticated users.
    app.get('/post-images-data', validateSession, async (req, res) => {
        try {
            const postId = parsePostId(getSafeString(req.query.postId).trim());
            if (postId === null) {
                return res.status(400).json([]);
            }

            const imagesResult = await pool.query(
                `SELECT image_id, mime_type, size_bytes
                 FROM post_images
                 WHERE post_id = $1
                 ORDER BY sort_order, image_id`,
                [postId]
            );

            return res.json(imagesResult.rows.map((row) => ({
                imageId: row.image_id,
                mimeType: row.mime_type,
                sizeBytes: row.size_bytes
            })));
        } catch (error) {
            console.error('Failed to load post images:', error.message);
            return res.status(500).json([]);
        }
    });

    // Return uploaded images only for authenticated users.
    app.get('/post-images/:imageId', validateSession, async (req, res) => {
        try {
            const imageId = Number.parseInt(String(req.params.imageId || ''), 10);
            if (!Number.isFinite(imageId)) {
                return res.status(400).end();
            }

            const imageResult = await pool.query(
                'SELECT image_data, mime_type FROM post_images WHERE image_id = $1',
                [imageId]
            );

            if (imageResult.rows.length === 0) {
                return res.status(404).end();
            }

            res.setHeader('Content-Type', imageResult.rows[0].mime_type);
            res.setHeader('Cache-Control', 'no-store');
            return res.send(imageResult.rows[0].image_data);
        } catch (error) {
            console.error('Failed to load image:', error.message);
            return res.status(500).end();
        }
    });

    app.get('/ping', validateSession, (req, res) => {
        res.json({ status: 'ok', username: req.currentUser });
    });

    // Fetch posts for the current user to display on the "My Posts" page.
    app.get('/my-posts-data', validateSession, async (req, res) => {
        try {
            const postsResult = await pool.query(`
                SELECT
                    posts.post_id,
                    COALESCE(NULLIF(users.display_name, ''), 'Unknown user') AS author_name,
                    posts.created_at_display,
                    posts.title,
                    posts.content
                FROM posts
                LEFT JOIN users ON LOWER(users.username) = LOWER(posts.username)
                WHERE posts.username = $1
                ORDER BY posts.post_id
            `, [req.currentUser]);

            return res.json(postsResult.rows.map(buildPostFromRow));
        } catch (error) {
            console.error('Failed to load user posts:', error.message);
            return res.status(500).json([]);
        }
    });

    // State-changing post routes also check the CSRF token before doing any work.
    // Create or edit a post with optional image uploads, ensuring all input is validated.
    app.post('/makepost', validateSession, validateCsrfToken, upload.array('image_files', LIMITS.maxImagesPerPost), async (req, res) => {
        try {
            const submittedPostId = getSafeString(req.body.postId).trim();
            const parsedPostId = parsePostId(submittedPostId);
            const title = getSafeString(req.body.title_field).trim();
            const content = getSafeString(req.body.content_field).trim();

            if (
                title === '' ||
                content === '' ||
                (submittedPostId !== '' && parsedPostId === null) ||
                !isWithinMaxLength(title, LIMITS.maxPostTitleLength) ||
                !isWithinMaxLength(content, LIMITS.maxPostContentLength)
            ) {
                return res.status(400).send('Invalid post data.');
            }

            if (containsHtmlLikeInput(title) || containsHtmlLikeInput(content)) {
                return res.status(400).send('Posts must use plain text only.');
            }

            const postId = parsedPostId ?? await getNextPostId(pool);
            const uploadedFiles = Array.isArray(req.files) ? req.files : [];
            const existingImageCountResult = await pool.query(
                'SELECT COUNT(*) AS count FROM post_images WHERE post_id = $1',
                [postId]
            );
            const existingImageCount = Number(existingImageCountResult.rows[0]?.count) || 0;

            // Ensure the total number of images (existing + new) does not exceed the allowed limit.
            if (existingImageCount + uploadedFiles.length > LIMITS.maxImagesPerPost) {
                return res.status(400).send(`You can upload up to ${LIMITS.maxImagesPerPost} images per post.`);
            }

            await pool.query(
                `INSERT INTO posts (post_id, username, created_at_display, title, content)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (post_id)
                 DO UPDATE SET
                    username = EXCLUDED.username,
                    created_at_display = EXCLUDED.created_at_display,
                    title = EXCLUDED.title,
                    content = EXCLUDED.content`,
                [postId, req.currentUser, getCurrentDisplayTimestamp(), title, encryptForDatabase(content)]
            );

            // Save uploaded images in the database, associating them with the post and maintaining sort order.
            for (let index = 0; index < uploadedFiles.length; index += 1) {
                const file = uploadedFiles[index];
                await pool.query(
                    `INSERT INTO post_images (post_id, filename, mime_type, size_bytes, image_data, sort_order)
                     VALUES ($1, $2, $3, $4, $5, $6)`,
                    [
                        postId,
                        file.originalname || null,
                        file.mimetype,
                        file.size,
                        file.buffer,
                        existingImageCount + index
                    ]
                );
            }

            return sendPage(res, PATHS.myPostsPage);
        } catch (error) {
            console.error('Failed to save encrypted post:', error.message);
            return res.status(500).send('Unable to save post.');
        }
    });

    // Delete a post by ID.
    app.post('/deletepost', validateSession, validateCsrfToken, async (req, res) => {
        try {
            const postId = parsePostId(getSafeString(req.body.postId).trim());
            if (postId === null) {
                return res.status(400).send('Invalid post ID.');
            }

            await pool.query('DELETE FROM posts WHERE post_id = $1', [postId]);
            return sendPage(res, PATHS.myPostsPage);
        } catch (error) {
            console.error('Failed to delete post:', error.message);
            return res.status(500).send('Unable to delete post.');
        }
    });

    // Allow users to delete only images from their own posts.
    app.post('/deleteimage', validateSession, validateCsrfToken, async (req, res) => {
        try {
            const imageId = Number.parseInt(getSafeString(req.body.imageId).trim(), 10);
            if (!Number.isFinite(imageId)) {
                return res.status(400).json({ ok: false });
            }

            const deleteResult = await pool.query(
                `DELETE FROM post_images
                 USING posts
                 WHERE post_images.image_id = $1
                   AND post_images.post_id = posts.post_id
                   AND posts.username = $2
                 RETURNING post_images.image_id`,
                [imageId, req.currentUser]
            );

            if (deleteResult.rowCount === 0) {
                return res.status(403).json({ ok: false });
            }

            return res.json({ ok: true });
        } catch (error) {
            console.error('Failed to delete image:', error.message);
            return res.status(500).json({ ok: false });
        }
    });
}

// Middleware to handle errors from Multer during file uploads, such as exceeding limits or invalid file types.
function handleUploadError(err, req, res, next) {
    if (err instanceof multer.MulterError) {
        return res.status(400).send('Image upload failed. Please check file size and count.');
    }

    if (err && err.code === 'INVALID_IMAGE_TYPE') {
        return res.status(400).send('Only PNG, JPG, or WEBP images are allowed.');
    }

    return next(err);
}

module.exports = {
    registerPostRoutes,
    handleUploadError
};
