const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();
app.use(express.json());

const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    username: { type: String, unique: true },
    passwordHash: String,
});

const UserModel = mongoose.models.User || mongoose.model('User', userSchema);

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await UserModel.findOne({ email });
    if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, 'secret', { expiresIn: '1h' });

    return res.status(200).json({
        token,
        user: {
            name: user.name,
            email: user.email,
        },
    });
});

let mongoServer;

beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();

    if (mongoose.connection.readyState === 0) {
        await mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true });
    }
});

afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
});

describe('POST /api/auth/login', () => {

    beforeEach(async () => {

        await UserModel.deleteMany({});

        // Create a unique user for each test
        await UserModel.create({
            name: 'Shreya Kuvalekar',
            email: 'shreyak96858n@pace.edu',
            username: 'shreyakuvalekar',
            passwordHash: await bcrypt.hash('Pass96858', 10),
        });
    });

    it('should login a user successfully and return 200 with user data and token', async () => {
        const response = await request(app)
            .post('/api/auth/login')
            .send({
                email: 'shreyak96858n@pace.edu',
                password: 'Pass96858',
            });

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('token');
        expect(response.body.user.name).toBe('Shreya Kuvalekar');
        expect(response.body.user.email).toBe('shreyak96858n@pace.edu');
    });

    it('should return 401 if the email is incorrect', async () => {
        const response = await request(app)
            .post('/api/auth/login')
            .send({
                email: 'shreykuvalekar@pace.edu',
                password: 'Password2025',
            });

        expect(response.status).toBe(401);
        expect(response.body.error).toBe('Invalid credentials');
    });

    it('should return 401 if the password is incorrect', async () => {
        const response = await request(app)
            .post('/api/auth/login')
            .send({
                email: 'shreyak96858n@pace.edu',
                password: 'shreya',
            });

        expect(response.status).toBe(401);
        expect(response.body.error).toBe('Invalid credentials');
    });

    it('should return 400 if required fields are missing', async () => {
        const response = await request(app)
            .post('/api/auth/login')
            .send({
                email: 'shreyak96858n@pace.edu',
            });

        expect(response.status).toBe(400);
        expect(response.body.error).toBe('Email and password are required');
    });

    it('should return 400 if email field is missing', async () => {
        const response = await request(app)
            .post('/api/auth/login')
            .send({
                password: 'Pass96858',
            });

        expect(response.status).toBe(400);
        expect(response.body.error).toBe('Email and password are required');
    });
});