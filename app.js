const express = require('express');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const dbPath = 'userData.db';
let db = null;

const JWT_SECRET = 'jkaksgmcjhla89kkah'; // Secret key for JWT 

// Initialize database and server
const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    app.listen(3000, () => {
      console.log('Server is running at http://localhost:3000/');
    });
  } catch (error) {
    console.log(`DB Error: ${error.message}`);
    process.exit(1);
  }
};

initializeDbAndServer();

// Middleware to verify JWT token
const authenticateToken = (request, response, next) => {
  const authHeader = request.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return response.status(401).send('Access Denied: No Token Provided!');
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return response.status(403).send('Invalid Token');
    }
    request.user = user; // Add the user info to the request
    next();
  });
};

// API 1: POST /register
app.post('/register', async (request, response) => {
  try {
    const { username, name, password, gender, location } = request.body;

    // Check if username already exists
    const userQuery = `SELECT * FROM user WHERE username = ?`;
    const existingUser = await db.get(userQuery, [username]);

    if (existingUser) {
      return response.status(400).send('User already exists');
    }

    // Check password length
    if (password.length < 5) {
      return response.status(400).send('Password is too short');
    }

    // Hash the password and insert new user
    const hashedPassword = await bcrypt.hash(password, 10);
    const insertUserQuery = `
      INSERT INTO user (username, name, password, gender, location)
      VALUES (?, ?, ?, ?, ?);
    `;
    await db.run(insertUserQuery, [
      username,
      name,
      hashedPassword,
      gender,
      location,
    ]);

    response.status(200).send('User created successfully');
  } catch (error) {
    response.status(500).send('Internal Server Error');
  }
});

// API 2: POST /login
app.post('/login', async (request, response) => {
  try {
    const { username, password } = request.body;

    // Check if user exists
    const userQuery = `SELECT * FROM user WHERE username = ?`;
    const user = await db.get(userQuery, [username]);

    if (!user) {
      return response.status(400).send('Invalid user');
    }

    // Check if password matches
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return response.status(400).send('Invalid password');
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    response.status(200).send({ message: 'Login success!', token });
  } catch (error) {
    response.status(500).send('Internal Server Error');
  }
});

// API 3: PUT /change-password (Protected Route)
app.put('/change-password', authenticateToken, async (request, response) => {
  try {
    const { oldPassword, newPassword } = request.body;
    const username = request.user.username; // Extract username from verified token

    // Check if user exists
    const userQuery = `SELECT * FROM user WHERE username = ?`;
    const user = await db.get(userQuery, [username]);

    if (!user) {
      return response.status(400).send('Invalid user');
    }

    // Check if old password matches
    const isOldPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isOldPasswordValid) {
      return response.status(400).send('Invalid current password');
    }

    // Check if new password is long enough
    if (newPassword.length < 5) {
      return response.status(400).send('Password is too short');
    }

    // Hash the new password and update the user's password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    const updatePasswordQuery = `UPDATE user SET password = ? WHERE username = ?`;
    await db.run(updatePasswordQuery, [hashedNewPassword, username]);

    response.status(200).send('Password updated');
  } catch (error) {
    response.status(500).send('Internal Server Error');
  }
});

//delete
app.delete('/delete-user', authenticateToken, async (request, response) => {
  try {
    const username = request.user.username; // Extract username from verified token

    // Delete the user from the database
    const deleteUserQuery = `DELETE FROM user WHERE username = ?`;
    const result = await db.run(deleteUserQuery, [username]);

    // Check if the user was actually deleted
    if (result.changes === 0) {
      return response.status(400).send('User not found or already deleted');
    }

    response.status(200).send('User deleted successfully');
  } catch (error) {
    response.status(500).send('Internal Server Error');
  }
});


module.exports = app;
