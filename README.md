# cyber-security-assessment-internship
Hashing Password

    // Hash password npm install bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    // Compare password during login
    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) {
        // Grant access
    } else {
        // Deny access
    }
Enhance Authentication

    npm install jsonwebtoken
    const jwt = require('jsonwebtoken');

    // Generate token
    const token = jwt.sign({ id: user._id }, 'your-secret-key', { expiresIn: '1h' });
    res.send({ token });

    // Verify token
    const decoded = jwt.verify(token, 'your-secret-key');
    console.log(decoded.id); // User ID
Secure Data Transmission

      const helmet = require('helmet');
app.use(helmet());

Example Implementation

Here’s how the updated index.js file might look after implementing the above measures: javascript Copy

require('dotenv').config(); const express = require('express'); const bcrypt = require('bcrypt'); const jwt = require('jsonwebtoken'); const helmet = require('helmet'); const validator = require('validator'); const app = express(); const port = process.env.PORT || 3000;

// Middleware app.use(express.json()); app.use(helmet());

// Example: User registration app.post('/register', async (req, res) => { try { const { email, password } = req.body;

    // Validate email
    if (!validator.isEmail(email)) {
        return res.status(400).send('Invalid email');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user to database (example)
    const user = { email, password: hashedPassword };
    res.status(201).send('User registered');
} catch (error) {
    res.status(500).send('Internal Server Error');
}
});

// Example: User login app.post('/login', async (req, res) => { try { const { email, password } = req.body; const user = { email, password: 'hashedPasswordFromDatabase' }; // Fetch user from DB

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send('Invalid credentials');

    // Generate token
    const token = jwt.sign({ id: user._id }, 'your-secret-key', { expiresIn: '1h' });
    res.send({ token });
} catch (error) {
    res.status(500).send('Internal Server Error');
}
});

// Example: Protected route app.get('/profile', (req, res) => { const token = req.header('Authorization')?.replace('Bearer ', ''); if (!token) return res.status(401).send('Access denied');

try {
    const decoded = jwt.verify(token, 'your-secret-key');
    res.send(`Welcome, user ${decoded.id}`);
} catch (error) {
    res.status(400).send('Invalid token');
}
});

// Start server app.listen(port, () => { console.log(Server is listening on port ${port}); });
