const request = require('supertest');

const testUserData = {
    name: 'Test User',
    email: 'test@example.com',
    password: 'secretPassword',
}

// Post to /auth/register
beforeAll(async () => {
    res = await request(global.__APP__)
    .post('/auth/register')
    .send({ name: testUserData.name, email: testUserData.email, password: testUserData.password });
})

describe('POST /auth/delete-user', () => {
    let res;
    let failedRes;
    beforeAll(async () => {
        res = await request(global.__APP__)
            .post('/auth/delete-user')
            .send({ email: testUserData.email });

        failedRes = await request(global.__APP__)
            .post('/auth/delete-user')
            .send({ email: 'thisIsNotPossible@gmail.com' });
    })
    it('should return a 200 status code', () => {
        expect(res.statusCode).toBe(200);
    })
    it('should contain a response body saying "Deleted User successfully"', () => {
        expect(res.body).toEqual({ message: 'Deleted User successfully' })
    })    
})
