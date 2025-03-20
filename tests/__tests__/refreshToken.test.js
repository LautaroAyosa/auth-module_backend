// Based on your existing test style:

const request = require('supertest');

const testUserData = {
  name: 'Refresh Token Test User',
  email: 'refresh-token-user@example.com',
  password: 'refreshSecretPassword'
};

let loginResponse;

beforeAll(async () => {
  // 1. Register a user
  await request(global.__APP__)
    .post('/auth/register')
    .send({
      name: testUserData.name,
      email: testUserData.email,
      password: testUserData.password
    });

  // 2. Log in to get refreshToken
  loginResponse = await request(global.__APP__)
    .post('/auth/login')
    .send({
      email: testUserData.email,
      password: testUserData.password
    });
});

describe('POST /auth/refresh-token', () => {
  it('should refresh access token successfully and return 200', async () => {
    const cookies = loginResponse.headers['set-cookie'];
    // Expect cookies to exist
    expect(cookies).toBeDefined();

    // Refresh token
    const refreshResponse = await request(global.__APP__)
      .post('/auth/refresh-token')
      .set('Cookie', cookies);

    expect(refreshResponse.statusCode).toBe(200);
    expect(refreshResponse.body).toHaveProperty('message', 'Access token refreshed');

    // Check new accessToken was returned as a cookie
    const newCookies = refreshResponse.headers['set-cookie'] || [];
    const hasAccessToken = newCookies.some(cookie => cookie.startsWith('accessToken='));
    expect(hasAccessToken).toBe(true);
  });

  it('should return 401 if no refresh token is provided', async () => {
    const response = await request(global.__APP__)
      .post('/auth/refresh-token');

    expect(response.statusCode).toBe(401);
    expect(response.body).toHaveProperty('error', 'No refresh token provided');
  });

  it('should return 401 if refresh token is invalid', async () => {
    // Provide a fake refresh token
    const response = await request(global.__APP__)
      .post('/auth/refresh-token')
      .set('Cookie', ['refreshToken=fakeInvalidToken']);

    expect(response.statusCode).toBe(401);
    expect(response.body).toHaveProperty('error', 'Invalid or expired refresh token');
  });

  it('should return 401 if refresh token is expired', async () => {

    const response = await request(global.__APP__)
      .post('/auth/refresh-token')
      .set('Cookie', ['refreshToken=expiredTokenExample']);

    expect(response.statusCode).toBe(401);
    expect(response.body).toHaveProperty('error', 'Invalid or expired refresh token');
  });

});
