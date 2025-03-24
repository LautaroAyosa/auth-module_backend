const jwt = require('jsonwebtoken');
const { generateAccessToken, setTokenCookies } = require('./tokenUtils');

const verifyToken = (token, secret) => {
    return jwt.verify(token, secret);
};

const refreshAccessToken = async (refreshToken, res, repositories) => {
    const { refreshTokenRepository, userRepository } = repositories;
    const tokenDoc = await refreshTokenRepository.findRefreshToken({ token: refreshToken });
    if (!tokenDoc || tokenDoc.expiresAt < new Date()) {
        throw new Error('Invalid or expired refresh token');
    }

    const user = await userRepository.findUserById({ id: tokenDoc.userId }, ['name', 'email', 'role']);
    if (!user) {
        throw new Error('User not found');
    }

    const newAccessToken = generateAccessToken(user);
    setTokenCookies(res, newAccessToken, refreshToken);

    return verifyToken(newAccessToken, process.env.JWT_SECRET);
};

module.exports = {
    verifyToken,
    refreshAccessToken
};