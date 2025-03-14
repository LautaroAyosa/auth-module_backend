const request = require('supertest');
const { initializeApp } = require('../../app');
const { disconnectMongo } = require('../../config/mongo');

let app;

const testUserData = { 
    name: 'Mongo Test User', 
    email: 'mongo@example.com', 
    password: 'secretPassword' 
}

beforeAll(async () => {
    // Initialize the app with Mongo config.
    app = await initializeApp({ dbType: 'mongo', mongoUri: process.env.MONGO_TEST_URI });
});
  
afterAll(async () => {
    // Disconnect from Mongo after tests finish.
    await disconnectMongo();
});
  
describe('Mongo API Tests', () => {
    describe('POST /auth/register', () => {

        let res;

        // Post to /auth/register
        beforeAll(async () => {
            res = await request(app)
          .post('/auth/register')
          .send({ name: testUserData.name, email: testUserData.email, password: testUserData.password });
        })

      it('should return a 201 status code', () => { expect(res.statusCode).toBe(201); });

      it('should return a user object with correct name and email', () => { 
        expect(res.body).toMatchObject({
            name: testUserData.name,
            email: testUserData.email,
    }); })
    });

    describe('POST /auth/login', () => {
        let res;
        let cookies;
        beforeAll(async () => {
            res = await request(app)
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
    })

    describe('POST /auth/logout', () => {
        let loginRes;
        let cookies;

        beforeAll(async () => {
            // Log in first to set the cookie
            loginRes = await request(app)
                .post('/auth/login')
                .send({ email: testUserData.email, password: testUserData.password });
            expect(loginRes.statusCode).toBe(200);
            expect(loginRes.headers['set-cookie']).toBeDefined();
            cookies = loginRes.headers['set-cookie'].join(';');
            expect(cookies).toMatch(/accessToken=/);
            expect(cookies).toMatch(/refreshToken=/);
        })
        
        it('should clear the cookies on logout', async () => {
            // Log out
            const res = await request(app).post('/auth/logout');
            // Verify the cookie is cleared (e.g., by checking it has an expiry in the past)
            const removedCookies = res.headers['set-cookie'].join(';');
            expect(removedCookies).toMatch(/accessToken=; Path=\/; Expires=/);
            expect(removedCookies).toMatch(/refreshToken=; Path=\/; Expires=/);
        });
    })
    

    describe('POST /auth/delete-user', () => {
        it('should delete a user', async () => {
            const res = await request(app)
                .post('/auth/delete-user')
                .send({ email: testUserData.email });
            expect(res.statusCode).toBe(200);
        })
    })

});