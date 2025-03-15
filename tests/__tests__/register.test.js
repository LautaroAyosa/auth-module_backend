const request = require('supertest');

describe('POST /auth/register', () => {
    let res;
    beforeAll( async () => {
        res = await request(global.__APP__)
        .post('/auth/register')
        .send({
            name: 'Test User',
            email: 'testuser@example.com',
            password: 'password123'
        });
    })
    it('should return a 201 status code', async () => {
        expect(res.statusCode).toBe(201);      
    });
    it('should return a user object with correct name and email', () => { 
        expect(res.body).toMatchObject({
            name: 'Test User',
            email: 'testuser@example.com',
        }); 
    })
    it('should not return password in the body', () => {
        expect(res.body).not.toHaveProperty('password');
    }) 
    it('should not return mfaSecret in the body', () => {
        expect(res.body).not.toHaveProperty('mfaSecret');
    }) 

    it('should return error 400 with informative error code for duplicate email', async () => {
        const userData = {
        name: 'Duplicate User',
        email: 'duplicate@example.com',
        password: 'password123'
        };

        // First registration should succeed
        await request(global.__APP__).post('/auth/register').send(userData);

        // Second registration with same email should fail
        const res = await request(global.__APP__)
        .post('/auth/register')
        .send({
            name: 'Duplicate User 2',
            email: 'duplicate@example.com',
            password: 'newpassword'
        });
        expect(res.statusCode).toBe(400);
        expect(res.body).toHaveProperty('error', 'Email already in use');
    });
});