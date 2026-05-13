# DSS Travel Blog

This project is a Node.js and Express travel blog web application.

## Requirements

Before running the project, make sure you have:

- Node.js installed
- npm installed
- PostgreSQL installed and running

## Installation

1. Open a terminal in the project folder.
2. Install the dependencies:

```bash
npm install
```

## Environment Variables

Create an `.env` file inside the `app` folder.

The application needs the following environment variables:

```env
DATABASE_URL=your_postgresql_connection_string
RECAPTCHA_SITE_KEY=your_recaptcha_site_key
RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key
AUTH0_SECRET=your_auth0_secret
AUTH0_BASE_URL=your_auth0_url
AUTH0_CLIENT_ID=your_auth0_client_id
AUTH0_ISSUER_BASE_URL=your_auth0_issuer_base_url
PASSWORD_PEPPER=your_password_pepper
DATABASE_ENCRYPTION_KEY=64_character_hex_key
```

## Running the Application

Start the server with:

```bash
npm start
```

The app should then be available at:

```text
http://localhost:3000
```

## Running Tests

To run all tests:

```bash
npm test
```

You can also run individual test files:

```bash
npm run test:hashing
npm run test:encryption
npm run test:signup
npm run test:posts
```
