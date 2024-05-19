const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');


const Server = express();

// Update CORS configuration to allow requests from your frontend EC2 instance
const corsOptions = {
    origin: '54.204.75.21', // replace with the frontend EC2 instance IP or domain
    methods: ['GET', 'POST'],
    credentials: false // if you're using cookies for session management
};

Server.use(cors(corsOptions));

// Database connection
const db = mysql.createConnection({
  host: 'myecommercewebsite.czc9puooeu5s.us-east-1.rds.amazonaws.com',
  user: 'root',
  password: 'root1234',
  database: 'myecommercewebsite'
});

// Connect to MySQL
db.connect((err) => {
  if (err) {
    throw err;
  }
  console.log('MySQL connected');
});

// Middleware
Server.use(bodyParser.json());
Server.use(express.static(path.join(__dirname, 'public')));
Server.use(session({
  
  resave: false,
  saveUninitialized: true,
  cookie: { secure: true } // set to true if using HTTPS
}));

// Registration Route
Server.post('/register', (req, res) => {
  const { username, email, password } = req.body;

  // Validate input
  if (!username || !email || !password) {
    return res.status(400).send('Please provide all required information');
  }

  // Check if email already exists
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) {
      console.error('Error checking for existing email:', err);
      return res.status(500).send('Error registering user');
    }
    if (results.length > 0) {
      return res.status(400).send('Email already exists');
    }

    // Hash the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        console.error('Error hashing password:', err);
        return res.status(500).send('Error hashing password');
      }

      // Insert user into database
      const sql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
      db.query(sql, [username, email, hashedPassword], (err, result) => {
        if (err) {
          console.error('Error inserting user into database:', err);
          return res.status(500).send('Error registering user');
        }
        res.send('Registration successful!');
      });
    });
  });
});

// Login Route
Server.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Validate input
  if (!username || !password) {
    return res.status(400).send('Please provide username and password');
  }

  // Check if username exists
  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) {
      console.error('Error checking for username:', err);
      return res.status(500).send('Error logging in');
    }
    if (results.length === 0) {
      return res.status(404).send('Username not registered');
    }

    // Compare passwords
    const user = results[0];
    bcrypt.compare(password, user.password, (err, match) => {
      if (err) {
        console.error('Error comparing passwords:', err);
        return res.status(500).send('Error logging in');
      }
      if (!match) {
        return res.status(401).send('Incorrect password');
      }

      // Set session or token for authentication
      // For simplicity, let's assume a session-based authentication
      req.session.user = { id: user.id, username: user.username, email: user.email };

      // Send a success message
      res.send('Login successful!');
    });
  });
});

Server.listen(3000, () => {
  console.log('Server is running on port 3000');
});

