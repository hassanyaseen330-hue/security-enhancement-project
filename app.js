const express = require('express');
const bcrypt = require('bcrypt');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
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

app.use(express.json());
app.use(helmet());

const users = [];

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
});});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const user = users.find(u => u.email === email);

    if (!user) {
        return res.status(401).send('User not found');
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
        return res.status(401).send('Invalid password');
    }

    const token = jwt.sign(
        { email: user.email },
        'my-secret-key'
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

app.listen(3000, () => {
  console.log('Server running on port 3000');
logger.info('Application started');
});

