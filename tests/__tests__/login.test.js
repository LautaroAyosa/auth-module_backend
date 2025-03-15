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

describe('POST /auth/login', () => {
    let res;
    let cookies;
    beforeAll(async () => {
        res = await request(global.__APP__)
            .post('/auth/login')
            .send({ email: testUserData.email, password: testUserData.password });
    })

    it('should return a 200 status code', () => {
        expect(res.statusCode).toBe(200);
    })
    it('should set cookies to client', () => {
        expect(res.headers['set-cookie']).toBeDefined();
        cookies = res.headers['set-cookie'].join(';');
    })
    it('should correctly set cookie called "accessToken"', () => {
        expect(cookies).toMatch(/accessToken=/);
    }) 
    it('should correctly set cookie called "refreshToken"', () => {
        expect(cookies).toMatch(/refreshToken=/);
    }) 
});