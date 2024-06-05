const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');
const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.json());

// MySQL connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'jwt_example'
});

// Connect to MySQL
db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL');
});

// Secret key for JWT
const JWT_SECRET = 'db_security';

// Helper function to authenticate JWT
const authenticateToken = (req, res, next) => {
    if(req.header('Authorization') == null) {
        return res.status(401).send('Unauthorized Access, please provide jwt token in the header!');
    }
    const token = req.header('Authorization').split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Register route
app.post('/register', (req, res) => {
    const { username, password } = req.body;

    // Hash the password
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: err });

        // Insert the user into the database
        db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], (err, results) => {
            if (err) return res.status(500).json({ error: err });

            res.status(201).json({ message: 'User registered successfully!' });
        });
    });
});

// Login route
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Find the user in the database
    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) return res.status(500).json({ error: err });
        if (results.length === 0) return res.status(401).json({ message: 'Invalid credentials' });

        const user = results[0];

        // Compare the password
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.status(500).json({ error: err });
            if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

            // Generate a JWT
            const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });

            res.json({ token });
        });
    });
});

// Protected route
app.get('/protected/:id', authenticateToken, (req, res) => {
    // Fetch protected information for the authenticated user
    db.query('SELECT * FROM protected_info WHERE user_id = ?', [req.params.id], (err, results) => {
        if (err) return res.status(500).json({ error: err });
        res.json({ protectedInfo: results });
    });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
