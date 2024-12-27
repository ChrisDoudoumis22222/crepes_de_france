require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');
const flash = require('connect-flash');

const app = express();
const PORT = process.env.PORT || 3000; // Use the Render-provided PORT

// Hardcoded users and passwords
const hardcodedUsers = {
    thanasis: 'thanasis123', // Password for Thanasis
    dimitris: 'dimitrisPass!', // Password for Dimitris
    user3: 'user3Secure#', // Password for User3
    argyris: 'dashboardpass', // User for dashboard access
    christos: 'christosPass@', // Password for Christos
};


// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configure session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'your_secret_key', // Use a secure secret in production
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true, // Helps mitigate XSS attacks
        secure: process.env.NODE_ENV === 'production', // Ensures HTTPS-only cookies in production
        maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
}));

// Flash message middleware
app.use(flash());

// Middleware to make flash messages available globally
app.use((req, res, next) => {
    res.locals.success_messages = req.flash('success');
    res.locals.error_messages = req.flash('error');
    next();
});

// Authentication middleware
function authenticate(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login.html'); // Redirect to login if not authenticated
    }
    next();
}

// Authorization middleware for dashboard access
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

// Serve login explicitly
app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve menu for authenticated users
app.get('/menuel.html', authenticate, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'menuel.html'));
});

// Serve dashboard for authorized users
app.get('/dashboard.html', authenticate, authorizeDashboard, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Handle login
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

    // Redirect based on user type
    if (username === 'dashboard_user') {
        return res.redirect('/dashboard.html');
    } else {
        return res.redirect('/menuel.html');
    }
});

// Handle logout
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
