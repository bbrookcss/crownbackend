const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db'); // Ensure this path is correct based on your project structure

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'your_secret_key'; // Use a strong secret key

// Middleware
app.use(bodyParser.json());
app.use(cors()); // Enable CORS

// Verify Token Middleware
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).json({ message: 'No token provided' });
  }

  jwt.verify(token.split(' ')[1], SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(500).json({ message: 'Failed to authenticate token', error: err.message });
    }

    req.userId = decoded.id;
    next();
  });
};

// Register a new user
app.post('/users/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  const hashedPassword = bcrypt.hashSync(password.toString(), 8);

  const query = `INSERT INTO users (username, password) VALUES (?, ?)`;
  db.run(query, [username, hashedPassword], function (err) {
    if (err) {
      return res.status(500).json({ message: 'Error registering user', error: err.message });
    }

    res.status(201).json({ id: this.lastID, username });
  });
});

// Login a user
app.post('/users/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Name and wedding day are required' });
  }

  const query = `SELECT id, username, password FROM users WHERE username = ?`;
  db.get(query, [username], (err, user) => {
    if (err) {
      return res.status(500).json({ message: 'Error logging in', error: err.message });
    }

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const passwordIsValid = bcrypt.compareSync(password.toString(), user.password);

    if (!passwordIsValid) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, {
      expiresIn: '1h', // Token expires in 1 hour
    });

    res.json({ id: user.id, username: user.username, token });
  });
});

// Get user page by ID
app.get('/users/:id', verifyToken, (req, res) => {
  const { id } = req.params;

  if (req.userId !== parseInt(id, 10)) {
    return res.status(403).json({ message: 'Access forbidden: invalid token for this user' });
  }

  const query = `SELECT id, username FROM users WHERE id = ?`;
  db.get(query, [id], (err, row) => {
    if (err) {
      return res.status(500).json({ message: 'Error retrieving user', error: err.message });
    }

    if (!row) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(row);
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
