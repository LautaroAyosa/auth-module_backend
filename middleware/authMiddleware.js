// Middleware for Auth and RBAC
const jwt = require('jsonwebtoken');

exports.requireAuth = (req, res, next) => {
    const accessToken = req.cookies?.accessToken;
    if (!accessToken) return res.status(401).json({ error: 'No access token provided' });

    try {
        const verified = jwt.verify(accessToken, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ error: 'Invalid Token' });
    }
};

exports.requireRole = (role) => (req, res, next) => {
    if (req.user.role !== role) {
        return res.status(403).json({ error: 'Access Forbidden: Insufficient Role' });
    }
    next();
};