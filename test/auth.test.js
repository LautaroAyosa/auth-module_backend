// Authentication Tests
const request = require('supertest');
const app = require('../app');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const User = require('../models/mongoose/User');
const RefreshToken = require('../models/mongoose/RefreshToken');

// Test Setup and Teardown
beforeAll(async () => {
    await mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
    await User.deleteMany(); // Clear test users
    await RefreshToken.deleteMany(); // Clear test tokens
});

afterAll(async () => {
    await mongoose.disconnect();
});

describe('Authentication Module', () => {
    let testUser;

    beforeEach(async () => {
        testUser = await User.create({
            name: 'Test User',
            email: 'testuser@example.com',
            password: await bcrypt.hash('password123', 10),
            role: 'user',
        });
    });

    afterEach(async () => {
        await User.deleteMany();
        await RefreshToken.deleteMany();
    });

    test('User can register', async () => {
        const res = await request(app).post('/auth/register').send({
            name: 'New User',
            email: 'newuser@example.com',
            password: 'password123',
        });
        expect(res.statusCode).toBe(201);
        expect(res.body.email).toBe('newuser@example.com');
    });

    test('User can login and receive tokens', async () => {
        const res = await request(app).post('/auth/login').send({
            email: 'testuser@example.com',
            password: 'password123',
        });
        expect(res.statusCode).toBe(200);
        expect(res.body.accessToken).toBeDefined();
        expect(res.body.refreshToken).toBeDefined();
    });

    test('MFA required for login if enabled', async () => {
        await User.findByIdAndUpdate(testUser.id, { mfaEnabled: true });
        const res = await request(app).post('/auth/login').send({
            email: 'testuser@example.com',
            password: 'password123',
        });
        expect(res.statusCode).toBe(200);
        expect(res.body.mfaRequired).toBe(true);
    });

    test('User can refresh access token', async () => {
        const refreshToken = await RefreshToken.create({
            token: 'valid_refresh_token',
            userId: testUser.id,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        });

        const res = await request(app).post('/auth/refresh-token').send({
            refreshToken: refreshToken.token,
        });

        expect(res.statusCode).toBe(200);
        expect(res.body.accessToken).toBeDefined();
    });

    test('Invalid refresh token returns error', async () => {
        const res = await request(app).post('/auth/refresh-token').send({
            refreshToken: 'invalid_token',
        });

        expect(res.statusCode).toBe(401);
        expect(res.body.error).toBe('Invalid or expired refresh token');
    });
});