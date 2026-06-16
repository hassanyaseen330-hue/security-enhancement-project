const express = require('express');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cors = require('cors');
const winston = require('winston')

const logger = winston.createLogger({
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({
            filename: 'security.log'
        })
    ]
});

const app = express();
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts. Please try again later.'
});

app.use(express.json());
app.use(cors({
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST'],
    credentials: true
}));
app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'"],
                styleSrc: ["'self'"]
            }
        }
    })
);

const users = [];
const API_KEY = 'my-secure-api-key';

app.post('/signup', async (req, res) => {
    const { email, password } = req.body;

    if (!validator.isEmail(email)) {
        return res.status(400).send('Invalid email');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    users.push({
        email,
        password: hashedPassword
    });

    res.send('User registered successfully');
});

function verifyApiKey(req, res, next) {

    const apiKey = req.headers['x-api-key'];

    if (apiKey !== 'my-secure-api-key') {
        return res.status(403).send('Invalid API Key');
    }

    next();
}
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
        return res.status(401).send('Access Denied');
    }

    const token = authHeader.split(' ')[1];

    jwt.verify(token, 'my-secret-key', (err, user) => {
        if (err) {
            return res.status(403).send('Invalid Token');
        }

        req.user = user;
        next();
    });
}
app.get('/profile', authenticateToken, (req, res) => {
    res.json({
        message: 'Protected Profile',
        user: req.user
    });
});

app.post('/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;

    const user = users.find(u => u.email === email);

   if (!user) {

    logger.warn(
        `Failed login attempt for email: ${email}`
    );

    return res.status(401).send('User not found');
}

    const match = await bcrypt.compare(password, user.password);

    if (!match) {

    logger.warn(
        `Invalid password attempt for email: ${email}`
    );

    return res.status(401).send('Invalid password');
}

   const token = jwt.sign(
    { email: user.email },
    'my-secret-key'
);

logger.info(
    `Successful login: ${email}`
);

res.json({ token });
});function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
        return res.status(401).send('Access Denied');
    }

    const token = authHeader.split(' ')[1];

    jwt.verify(token, 'my-secret-key', (err, user) => {
        if (err) {
            return res.status(403).send('Invalid Token');
        }

        req.user = user;
        next();
   });
}
   app.get('/profile', authenticateToken, (req, res) => {
    res.json({
        message: 'Protected Profile',
        user: req.user
    });
});

app.use((err, req, res, next) => {
    console.error(err.stack);

    res.status(500).json({
        error: 'Something went wrong'
    });
});

app.get('/secure-data', verifyApiKey, (req, res) => {

    res.json({
        message: 'Secure API Access Granted'
    });

});
app.get('/security-status', (req, res) => {

    res.json({
        status: 'Secure',
        authentication: 'Enabled',
        jwt: 'Enabled',
        passwordHashing: 'Enabled',
        logging: 'Enabled',
        rateLimiting: 'Enabled',
        cors: 'Enabled',
        helmet: 'Enabled'
    });

});
app.listen(3000, () => {
  console.log('Server running on port 3000');
logger.info('Application started');
});

