
const { requireAuth, requireRole } = require('../middleware/authMiddleware');
const authRouter = require('express').Router();

module.exports = (repositories) => {
    const { 
        register,
        login,
        logout,
        updateUser,
        updateEmail,
        deleteUser,
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
    } = require('../controllers/authController')(repositories);

    // POST Routes
    authRouter.post('/register', register);
    authRouter.post('/login', login);
    authRouter.post('/logout', logout);
    authRouter.post('/delete-user', deleteUser);
    authRouter.post('/make-admin', requireAuth, requireRole('admin'), makeAdmin);
    authRouter.post('/enable-mfa', enableMFA);
    authRouter.post('/verify-mfa', verifyMFA);
    authRouter.post('/recover-mfa', recoverMFA);
    authRouter.post('/reset-mfa', requireAuth, requireRole('admin'), resetMFA);
    authRouter.post('/refresh-token', refreshToken);
    authRouter.post('/request-reset-password', requestPasswordReset);
    authRouter.post('/reset-password', resetPassword);
    
    // PUT Routes
    authRouter.put('/update-user', updateUser);
    authRouter.put('/update-email/:token', updateEmail);
    
    // GET Routes
    authRouter.get('/google', googleAuth);
    authRouter.get('/validate-session', validateSession);
    authRouter.get('/admin', requireAuth, requireRole('admin', protectedRoute));
    authRouter.get('/user', requireAuth, requireRole('user', protectedRoute));

    return authRouter;
}