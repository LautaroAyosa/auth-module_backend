
const { requireAuth, requireRole } = require('../middleware/authMiddleware');
const authRouter = require('express').Router();

// module.exports = authRouter;

module.exports = (repositories) => {

    const authController = require('../controllers/authController')(repositories);

    const { 
        register,
        login,
        logout,
        makeAdmin,
        enableMFA,
        verifyMFA,
        recoverMFA,
        resetMFA,
        refreshToken,
        requestPasswordReset,
        resetPassword,
        googleAuth,
        validateSession,
        protectedRoute,
        test,
    } = require('../controllers/authController')(repositories);

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


    authRouter.post('/test', test);
    return authRouter;
}