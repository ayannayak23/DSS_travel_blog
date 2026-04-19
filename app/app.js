const express = require('express')
const app = express();
const port = 3000;

var bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const { Pool } = require('pg');

dotenv.config({ path: path.join(__dirname, '.env') });

app.use(express.static(__dirname + '/public'));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

const dbConnectionString = process.env.DATABASE_URL || process.env.DATABASE_URL;

if (!dbConnectionString) {
    console.error('Missing DATABASE_URL (or DATABASE_URL) in app/.env.');
    process.exit(1);
}

const pool = new Pool({
    connectionString: dbConnectionString,
    ssl: {
        rejectUnauthorized: false
    }
});

// Landing page
app.get('/', (req, res) => {
    /// send the static file
    res.sendFile(__dirname + '/public/html/login.html', (err) => {
        if (err){
            console.log(err);
        }
    })
});

// Store who is currently logged in
let currentUser = null;
let loginStatus = 'none';

function sendLoginPage(res) {
    res.sendFile(__dirname + '/public/html/login.html', (err) => {
        if (err){
            console.log(err);
        }
    });
}

app.get('/login-status', (req, res) => {
    res.json({ status: loginStatus });
});

app.get('/current-user', (req, res) => {
    res.json({ username: currentUser });
});

// Login POST request
app.post('/', async function(req, res){

    // Get username and password entered from user
    var username = (req.body.username_input || '').trim();
    var password = req.body.password_input || '';

    if (username === '' || password === '') {
        currentUser = null;
        loginStatus = 'empty';
        return sendLoginPage(res);
    }

    try {
        // Intentionally plaintext comparison for coursework behavior.
        const userResult = await pool.query(
            'SELECT username, password FROM users WHERE username = $1 LIMIT 1',
            [username]
        );

        if (userResult.rows.length === 0) {
            currentUser = null;
            loginStatus = 'bad_username';
            return sendLoginPage(res);
        }

        if (userResult.rows[0].password !== password) {
            currentUser = null;
            loginStatus = 'bad_password';
            return sendLoginPage(res);
        }

        loginStatus = 'success';
        currentUser = username;

        return res.sendFile(__dirname + '/public/html/index.html', (err) => {
            if (err){
                console.log(err);
            }
        });
    } catch (error) {
        console.error('Login query failed:', error.message);
        currentUser = null;
        loginStatus = 'server_error';
        return sendLoginPage(res);
    }
});

// Make a post POST request
app.post('/makepost', function(req, res) {

    // Read in current posts
    const json = fs.readFileSync(__dirname + '/public/json/posts.json');
    var posts = JSON.parse(json);

    // Get the current date
    let curDate = new Date();
    curDate = curDate.toLocaleString("en-GB");

    // Find post with the highest ID
    let maxId = 0;
    for (let i = 0; i < posts.length; i++) {
        if (posts[i].postId > maxId) {
            maxId = posts[i].postId;
        }
    }

    // Initialise ID for a new post
    let newId = 0;

    // If postId is empty, user is making a new post
    if(req.body.postId == "") {
        newId = maxId + 1;
    } else { // If postID != empty, user is editing a post
        newId = req.body.postId;

        // Find post with the matching ID, delete it from posts so user can submit their new version
        let index = posts.findIndex(item => item.postId == newId);
        posts.splice(index, 1);
    }

    // Add post to posts.json
    posts.push({"username": currentUser , "timestamp": curDate, "postId": newId, "title": req.body.title_field, "content": req.body.content_field});

    fs.writeFileSync(__dirname + '/public/json/posts.json', JSON.stringify(posts));

    // Redirect back to my_posts.html
    res.sendFile(__dirname + "/public/html/my_posts.html");
 });

 // Delete a post POST request
 app.post('/deletepost', (req, res) => {

    // Read in current posts
    const json = fs.readFileSync(__dirname + '/public/json/posts.json');
    var posts = JSON.parse(json);

    // Find post with matching ID and delete it
    let index = posts.findIndex(item => item.postId == req.body.postId);
    posts.splice(index, 1);

    // Update posts.json
    fs.writeFileSync(__dirname + '/public/json/posts.json', JSON.stringify(posts));

    res.sendFile(__dirname + "/public/html/my_posts.html");
 });

pool.query('SELECT 1')
    .then(() => {
        app.listen(port, () => {
            console.log(`My app listening on port ${port}!`)
        });
    })
    .catch((error) => {
        console.error('Failed to connect to PostgreSQL:', error.message);
        process.exit(1);
    });