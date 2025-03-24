const { validate, schemas } = require('../middleware/validationMiddleware');

const authRouter = require('express').Router();

module.exports = (repositories) => {
    const { requireAuth, requireRole } = require('../middleware/authMiddleware')(repositories);
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
        getAllUsers,
    } = require('../controllers/authController')(repositories);


    // POST Routes
    authRouter.post('/register', validate(schemas.register), register);
    authRouter.post('/login', validate(schemas.login), login);
    authRouter.post('/logout', logout);
    authRouter.post('/delete-user', deleteUser);
    authRouter.post('/make-admin', requireAuth, requireRole('admin'), makeAdmin);
    authRouter.post('/enable-mfa', requireAuth, enableMFA);
    authRouter.post('/verify-mfa', verifyMFA);
    authRouter.post('/recover-mfa', recoverMFA);
    authRouter.post('/reset-mfa', requireAuth, requireRole('admin'), resetMFA);
    authRouter.post('/refresh-token', refreshToken);
    authRouter.post('/request-reset-password', validate(schemas.requestPasswordReset), requestPasswordReset);
    authRouter.post('/reset-password', validate(schemas.resetPassword), resetPassword);
    
    // PUT Routes
    authRouter.put('/update-user', requireAuth, validate(schemas.updateUser), updateUser);
    authRouter.put('/update-email/:token', updateEmail);

    // DELETE Routes
    authRouter.delete('/delete-user', requireAuth, requireRole('admin'), deleteUser);
    
    // GET Routes
    authRouter.get('/get-all-users', requireAuth, requireRole('admin'), getAllUsers);
    authRouter.get('/google', googleAuth);
    authRouter.get('/validate-session', requireAuth, validateSession);
    authRouter.get('/admin', requireAuth, requireRole('admin', protectedRoute));
    authRouter.get('/user', requireAuth, requireRole('user', protectedRoute));

    return authRouter;
}