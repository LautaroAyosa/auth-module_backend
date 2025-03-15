const request = require('supertest')

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

describe('POST /auth/logout - Logout Flow', () => {
    let cookies;
    let logoutResponse;
  
    beforeAll(async () => {
      // Log in the user and capture cookies
      const loginResponse = await request(global.__APP__)
        .post('/auth/login')
        .send({
          email: testUserData.email,
          password: testUserData.password
        });
      cookies = loginResponse.headers['set-cookie'];
      expect(cookies).toBeDefined();
      expect(cookies.length).toBeGreaterThan(0);
  
      // Log out using the captured cookies
      logoutResponse = await request(global.__APP__)
        .post('/auth/logout')
        .set('Cookie', cookies)
        .send();
    });
  
    it('should return a 200 status code', () => {
      expect(logoutResponse.statusCode).toBe(200);
    });
  
    it('should contain a response body saying "Logged out successfully"', () => {
      expect(logoutResponse.body).toEqual({ message: 'Logged out successfully' });
    });
  
    it('should clear the accessToken cookie', () => {
      const logoutCookies = logoutResponse.headers['set-cookie'] || [];
      const accessTokenCleared = logoutCookies.some(cookie =>
        cookie.startsWith('accessToken=;')
      );
      expect(accessTokenCleared).toBe(true);
    });
  
    it('should clear the refreshToken cookie', () => {
      const logoutCookies = logoutResponse.headers['set-cookie'] || [];
      const refreshTokenCleared = logoutCookies.some(cookie =>
        cookie.startsWith('refreshToken=;')
      );
      expect(refreshTokenCleared).toBe(true);
    });
  });