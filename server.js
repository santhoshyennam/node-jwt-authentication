const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');
const session = require('express-session');
const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.json());
app.use(session({
    secret: 'db_security',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Use secure: true in production with HTTPS
}));

// MySQL connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'session_example'
});

// Connect to MySQL
db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL');
});

// Helper function to authenticate session
const authenticateSession = (req, res, next) => {
    if (!req.session.user) {
        return res.status(401).send('Unauthorized Access, please log in!');
    }
    next();
};

// Register route
app.post('/signup', (req, res) => {
    const { email, password } = req.body;

    // Hash the password
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: err });

        // Insert the user into the database
        db.query('INSERT INTO users (username, password) VALUES (?, ?)', [email, hash], (err, results) => {
            if (err) return res.status(500).json({ error: err });

            res.status(201).json({ message: 'User registered successfully!' });
        });
    });
});

// Login route
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    // Find the user in the database
    db.query('SELECT * FROM users WHERE username = ?', [email], (err, results) => {
        if (err) return res.status(500).json({ error: err });
        if (results.length === 0) return res.status(401).json({ message: 'Invalid credentials' });

        const user = results[0];

        // Compare the password
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.status(500).json({ error: err });
            if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

            // Create a session
            req.session.user = { id: user.id, email: user.username };
            res.json({ message: 'Logged in successfully!' });
        });
    });
});

app.get('/getinfo/:id', authenticateSession, (req, res) => {
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