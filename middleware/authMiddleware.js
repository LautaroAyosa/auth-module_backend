const { verifyToken, refreshAccessToken } = require('../utils/verifyToken');
const handleError = require('../utils/errorHandler');

module.exports = (repositories) => {
    return {
        requireAuth: async (req, res, next) => {
            const { accessToken, refreshToken } = req.cookies;

            if (!accessToken && refreshToken) {
                try {
                    req.user = await refreshAccessToken(refreshToken, res, repositories);
                    return next();
                } catch (err) {
                    return handleError(res, 401, err.message);
                }
            }

            if (!accessToken && !refreshToken) {
                return handleError(res, 401, 'No access or refresh token provided');
            }

            try {
                const verified = verifyToken(accessToken, process.env.JWT_SECRET);
                req.user = verified;
                next();
            } catch (err) {
                if (err.name === 'TokenExpiredError' && refreshToken) {
                    try {
                        req.user = await refreshAccessToken(refreshToken, res, repositories);
                        return next();
                    } catch (refreshErr) {
                        return handleError(res, 401, refreshErr.message);
                    }
                } else {
                    return handleError(res, 400, 'Invalid Token');
                }
            }
        },
        requireRole: (role) => (req, res, next) => {
            if (req.user.role !== role) {
                return handleError(res, 403, 'Access Forbidden: Insufficient Role');
            }
            next();
        },
        errorHandler: (err, req, res, next) => {
            console.error(err.stack);
            handleError(res, 500, 'Internal Server Error');
        }
    };
};