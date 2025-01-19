const {register, login, logout, resetPassword, googleAuth, protectedRoute, makeAdmin, enableMFA, verifyMFA, recoverMFA, resetMFA, refreshToken, validateSession, requestPasswordReset} = require('../controllers/authController');
const { requireAuth, requireRole } = require('../middleware/authMiddleware');
const authRouter = require('express').Router();

// POST Routes
authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.post('/logout', logout);
authRouter.post('/make-admin', requireAuth, requireRole('admin'), makeAdmin);
authRouter.post('/enable-mfa', enableMFA);
authRouter.post('/verify-mfa', verifyMFA);
authRouter.post('/recover-mfa', recoverMFA);
authRouter.post('/reset-mfa', requireAuth, requireRole('admin'), resetMFA);
authRouter.post('/refresh-token', refreshToken);
authRouter.post('/request-reset-password', requestPasswordReset);
authRouter.post('/reset-password', resetPassword);

// GET Routes
authRouter.get('/google', googleAuth);
authRouter.get('/validate-session', validateSession);
authRouter.get('/admin', requireAuth, requireRole('admin', protectedRoute));
authRouter.get('/user', requireAuth, requireRole('user', protectedRoute));

module.exports = authRouter;