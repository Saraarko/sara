 # Backend API Documentation

This backend is built using Flask and provides a secure API for user authentication and password management. Below is a comprehensive list of all available endpoints.

## Base URL
All endpoints are prefixed with `/api`

## Authentication Endpoints

### User Registration and Login
- `POST /api/register` - Register a new user
  - Request Body: `{ "username": string, "password": string }`
  - Response: `{ "message": string, "token": string, "user_file": string }`

- `POST /api/login` - Login with username and password
  - Request Body: `{ "username": string, "password": string }`
  - Response: `{ "message": string, "token": string }`

- `POST /api/logout` - Logout user
  - Response: `{ "message": string }`

### Google Authentication
- `GET /login/callback` - Google OAuth callback endpoint
  - Response: `{ "message": string, "token": string }`

### Password Management
- `POST /api/change-password` - Change user password
  - Headers: `Authorization: Bearer <token>`
  - Request Body: `{ "old_password": string, "new_password": string }`
  - Response: `{ "message": string }`

## Password Storage Endpoints

### Password Operations
- `POST /api/passwords` - Save a new password
  - Headers: `Authorization: Bearer <token>`
  - Request Body: `{ "hashed_password": string, "encrypted_data": string }`
  - Response: `{ "message": string }`

- `GET /api/passwords/<username>` - Get user's passwords
  - Headers: `Authorization: Bearer <token>`
  - Query Params: `hashed_password`
  - Response: `{ "encrypted_data": string }`

- `PUT /api/passwords/<password_id>` - Update a password
  - Headers: `Authorization: Bearer <token>`
  - Request Body: `{ "hashed_password": string, "encrypted_data": string }`
  - Response: `{ "message": string }`

- `DELETE /api/passwords/<password_id>` - Delete a password
  - Headers: `Authorization: Bearer <token>`
  - Response: `{ "message": string }`

## Data Management Endpoints

### Data Operations
- `POST /api/write-data` - Write encrypted data
  - Headers: `Authorization: Bearer <token>`
  - Request Body: `{ "hashed_password": string, "encrypted_data": string }`
  - Response: `{ "message": string }`

- `GET /api/read-data` - Read encrypted data
  - Headers: `Authorization: Bearer <token>`
  - Query Params: `hashed_password`
  - Response: `{ "encrypted_data": string }`

## Utility Endpoints

### Health Check
- `GET /api/health` - Check API health
  - Response: `{ "status": "ok" }`

## Security Features
- All endpoints (except health check) require JWT authentication
- Passwords are hashed using SHA-256
- Data is encrypted using Fernet (symmetric encryption)
- Google OAuth integration for alternative authentication
- Automatic backup system for user data

## Dependencies
- Flask
- Flask-CORS
- PyJWT
- Cryptography
- Python-dotenv
- Google Auth Library (for Google OAuth)

## Environment Variables Required
- `SECRET_KEY` - Flask secret key
- `JWT_SECRET_KEY` - JWT signing key
- `GOOGLE_CLIENT_ID` - Google OAuth client ID
- `GOOGLE_CLIENT_SECRET` - Google OAuth client secret
