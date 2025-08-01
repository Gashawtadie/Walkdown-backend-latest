# Walkdown Backend API

A Node.js/Express backend API for user authentication and management with PostgreSQL database.

## Features

- User registration and login
- JWT-based authentication
- Password reset with OTP
- PostgreSQL database integration
- CORS enabled
- Input validation and error handling

## Prerequisites

- Node.js (v14 or higher)
- PostgreSQL database
- npm or yarn

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd Walkdown-backend-latest
```

2. Install dependencies:
```bash
npm install
```

3. Set up environment variables:
```bash
cp env.example .env
```
Edit the `.env` file with your database credentials and JWT secret.

4. Set up the database:
Create a PostgreSQL database and run the following SQL to create the users table:

```sql
CREATE TABLE users (
    userid SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    firstname VARCHAR(50) NOT NULL,
    lastname VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    otp VARCHAR(6),
    otp_expires TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Usage

### Development
```bash
npm run dev
```

### Production
```bash
npm start
```

The server will start on port 3000 (or the port specified in your .env file).

## API Endpoints

### Authentication
- `POST /api/users/register` - Register a new user
- `POST /api/users/login` - Login user
- `GET /api/users/check` - Check user authentication (requires token)
- `POST /api/users/forgot-password` - Request password reset OTP
- `POST /api/users/reset-password` - Reset password with OTP

### Request/Response Examples

#### Register User
```json
POST /api/users/register
{
    "username": "john_doe",
    "firstname": "John",
    "lastname": "Doe",
    "email": "john@example.com",
    "password": "securepassword123"
}
```

#### Login User
```json
POST /api/users/login
{
    "email": "john@example.com",
    "password": "securepassword123"
}
```

#### Request Password Reset
```json
POST /api/users/forgot-password
{
    "email": "john@example.com"
}
```

#### Reset Password
```json
POST /api/users/reset-password
{
    "email": "john@example.com",
    "otp": "123456",
    "password": "newpassword123"
}
```

## Environment Variables

- `DATABASE_URL` - PostgreSQL connection string
- `JWT_SECRET` - Secret key for JWT token signing
- `PORT` - Server port (default: 3000)
- `SSL_REJECT_UNAUTHORIZED` - SSL configuration for database

## Security Features

- Password hashing with bcrypt
- JWT token authentication
- Input validation
- SQL injection prevention with parameterized queries
- CORS protection

## Error Handling

The API returns appropriate HTTP status codes and error messages for various scenarios:
- 400 Bad Request - Invalid input data
- 401 Unauthorized - Invalid or missing authentication
- 404 Not Found - Resource not found
- 500 Internal Server Error - Server-side errors