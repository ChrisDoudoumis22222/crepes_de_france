// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');
const flash = require('connect-flash'); // Optional for flash messages

const app = express();
const PORT = process.env.PORT || 3000;

// Hardcoded users and passwords
const hardcodedUsers = {
    admin: 'admin123',
    john_doe: 'password1',
    jane_smith: 'mysecretpass',
    dashboard_user: 'dashboardpass', // New user for redirecting to dashboard.html
};

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configure session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'your_secret_key', // Use a strong secret in production
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true, // Mitigates XSS attacks
        secure: process.env.NODE_ENV === 'production', // Ensures the browser only sends the cookie over HTTPS
        maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
}));

// Initialize flash middleware
app.use(flash());

// Middleware to make flash messages available in all templates (if using template engines)
app.use((req, res, next) => {
    res.locals.success_messages = req.flash('success');
    res.locals.error_messages = req.flash('error');
    next();
});

// Middleware to authenticate users
function authenticate(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login.html'); // Redirect to login if not authenticated
    }
    next();
}

// Middleware to authorize access to dashboard.html
function authorizeDashboard(req, res, next) {
    if (req.session.user && req.session.user.username === 'dashboard_user') {
        return next();
    }
    res.status(403).send('Access denied'); // Restrict access for non-dashboard users
}

// Serve login.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve login.html explicitly for clarity
app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve menuel.html (accessible by all authenticated users)
app.get('/menuel.html', authenticate, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'menuel.html'));
});

// Serve dashboard.html (restricted to 'dashboard_user')
app.get('/dashboard.html', authenticate, authorizeDashboard, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Route to handle login
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        req.flash('error', 'Missing username or password');
        return res.redirect('/login.html');
    }

    if (hardcodedUsers[username] !== password) {
        req.flash('error', 'Invalid username or password');
        return res.redirect('/login.html');
    }

    // Establish session
    req.session.user = { username };

    if (username === 'dashboard_user') {
        return res.redirect('/dashboard.html');
    } else {
        return res.redirect('/menuel.html');
    }
});

// Route to handle logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.redirect('/');
        }
        res.clearCookie('connect.sid');
        res.redirect('/login.html');
    });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
