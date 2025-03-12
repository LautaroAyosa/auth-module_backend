// Auth Controller. Functions for Auth
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const speakeasy = require('speakeasy');
const crypto = require('crypto');
const qrcode = require('qrcode');
const sendEmail = require('../utils/sendEmail'); // Implement an email utility

module.exports = (repositories) => {
    const userRepository = repositories.userRepository;
    const refreshTokenRepository = repositories.refreshTokenRepository;
    const temporarySessionRepository = repositories.temporarySessionRepository;
    const passwordResetTokenRepository = repositories.passwordResetTokenRepository;

    const generateAccessToken = (user) => {
        return jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '15m' });
    };
    
    const generateRefreshToken = async (userId) => {
        const token = crypto.randomBytes(40).toString('hex');
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
        await refreshTokenRepository.createRefreshToken({ 
            token: token, 
            userId: userId, 
            expiresAt: expiresAt
        });
        return token;
    };

    return {
        test: async (req, res) => {
            const token = crypto.randomBytes(32).toString('hex');
            const token2 = crypto.randomBytes(32).toString('hex');
            const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
            // "67d1bb2be903677543a1155b"
            const newToken = await passwordResetTokenRepository.createPasswordResetToken({
                token: token,
                userId: 1,
                expiresAt: expiresAt
            })
            const findOne = await passwordResetTokenRepository.findPasswordResetToken({token: token})
            const deleteOne = await passwordResetTokenRepository.deletePasswordResetToken({token: token})
            const findNotAvailable = await passwordResetTokenRepository.findPasswordResetToken({token: token})
            res.json({
                "newToken": newToken,
                "findOne": findOne,
                "deleteOne": deleteOne,
                "findDeleted": findNotAvailable
            });
            try {
            } catch (err) {
                res.status(500).json({ error: 'Error getting users', err });
            }
        },
        validateSession: async (req, res) => {
            const accessToken = req.cookies?.accessToken;
            if (!accessToken) {
                return res.status(401).json({ error: 'No access token provided'})
            }
            try {
                // Check if accessToken is valid
                const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
                const user = await userRepository.findUserById({id: decoded.id});
                res.json({ authenticated: true, user: { id: user.id, name: user.name, email: user.email, mfaEnabled: user.mfaEnabled, role: user.role } });
            } catch (err) {
                // If accessToken is expired, try refreshing it
                if (err.name === 'TokenExpiredError') {
                    const refreshToken = req.cookies?.refreshToken;
                    if (!refreshToken) {
                        return res.status(401).json({ authenticated: false });
                    }
        
                    try {
                        const tokenDoc = await refreshTokenRepository.findRefreshToken({ token: refreshToken });
                        if (!tokenDoc || tokenDoc.expiresAt < new Date()) {
                            return res.status(401).json({ error: 'Invalid or expired refresh token' });
                        }
        
                        const user = await userRepository.findUserById({id: tokenDoc.userId});
                        
                        // Generate a new access token
                        const newAccessToken = generateAccessToken(user);
        
                        // Set the new accessToken as an HTTP-only cookie
                        res.cookie('accessToken', newAccessToken, {
                            httpOnly: true,
                            secure: process.env.NODE_ENV === 'production',
                            sameSite: 'strict',
                            maxAge: 15 * 60 * 1000, // 15 minutes
                        });
        
                        res.json({ authenticated: true, user: { id: user.id, name: user.name, email: user.email, role: user.role, mfaEnabled: user.mfaEnabled } });
                    } catch (refreshError) {
                        res.status(403).json({ authenticated: false });
                    }
                } else {
                    res.status(403).json({ authenticated: false });
                }
            }
        },
        register: async (req, res) => {
            const { name, email, password } = req.body;
            try {
                const hashedPassword = await bcrypt.hash(password, 10);
        
                const user = await userRepository.createUser({ 
                    name: name, 
                    email: email, 
                    password: hashedPassword 
                });
                res.status(201).json(user);
            } catch (err) {
                res.status(500).json({ error: 'Error registering user', err });
            }
        },
        login: async (req, res) => {
            const { email, password } = req.body;
            
            try {
                const user = await userRepository.findUserByEmail({ email: email });
                // Check if the credentials are correct
                if (!user || !(await bcrypt.compare(password, user.password))) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }
        
                // Check if MFA is enabled. If it is, exit with json res 200 
                // meaning that everything is okay, but you need an extra step (MFA).
                // This also includes a tempSessionID for security reasons.
                if (user.mfaEnabled) {
                    const tempSessionId = crypto.randomBytes(16).toString('hex');
                    await temporarySessionRepository.createTemporarySession({ 
                        userId: user.id, 
                        sessionId: tempSessionId 
                    });
        
                    return res.status(200).json({
                        mfaRequired: true,
                        tempSessionId,
                        message: 'MFA verification required',
                    });
                }
                // Issue token if MFA is not enabled
                const accessToken = generateAccessToken(user);
                const refreshToken = await generateRefreshToken(user.id);
                // Set tokens as HTTP-only cookies
                res.cookie('accessToken', accessToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
                    sameSite: 'strict',
                    maxAge: 15 * 60 * 1000, // 15 minutes
                });
                res.cookie('refreshToken', refreshToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'strict',
                    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
                });
        
                res.json({ message: 'Login successful' });        
            } catch (err) {
                res.status(500).json({ error: 'Error logging in' });
            }
        },
        logout: async (req, res) => {
            const { refreshToken } = req.cookies;
            try {
                await refreshTokenRepository.deleteRefreshToken({ token: refreshToken });
                res.clearCookie('accessToken');
                res.clearCookie('refreshToken');
                res.json({ message: 'Logged out successfully' });
            } catch (err) {
                res.status(500).json({ error: 'Error logging out' });
            }
        },
        refreshToken: async (req, res) => {
            const { refreshToken } = req.cookies;
            if (!refreshToken) return res.status(401).json({ error: 'No refresh token provided' });
            try {
                const tokenDoc = await refreshTokenRepository.findRefreshToken({ token: refreshToken });
                if (!tokenDoc || tokenDoc.expiresAt < new Date()) {
                    return res.status(401).json({ error: 'Invalid or expired refresh token' });
                }
        
                const user = await userRepository.findUserById({ id: tokenDoc.userId });
                const newAccessToken = generateAccessToken(user);
                // Set new access token as HTTP-only cookie
                res.cookie('accessToken', newAccessToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'strict',
                    maxAge: 15 * 60 * 1000, // 15 minutes
                });
                res.statis(200).json({ message: 'Access token refreshed' });
            } catch (err) {
                res.status(500).json({ error: 'Error refreshing token' });
            }
        },
        googleAuth: async (req, res) => {
            try {
                passport.authenticate('google', { scope: ['profile', 'email'] });
            } catch (err) {

            }
        },
        protectedRoute: (req, res) => {
            res.json({ message: 'Welcome to the protected admin route!' });
        },
        makeAdmin: async (req, res) => {
            const { id } = req.body;
            try {
                const user = await userRepository.updateUser( { id: id }, { role: 'admin' });
                if (!user) return res.status(404).json({ error: 'User not found' });
                res.json({ message: `User ${user.email} is now an admin`, user });
            } catch (err) {
                res.status(500).json({ error: 'Error updating user role' });
            }
        },
        enableMFA: async (req, res) => {
            const accessToken = req.cookies?.accessToken;
            if (!accessToken) {
                return res.status(401).json({ authenticated: false, error: 'No access token provided'})
            }
            try {
                const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
        
                const secret = speakeasy.generateSecret({
                    name: `${process.env.APP_NAME} (${decoded.email})`, // Token Name
                });
        
                const recoveryCode = crypto.randomBytes(16).toString('hex'); // Generate recovery code
                const hashedRecoveryCode = await bcrypt.hash(recoveryCode, 10);
        
        
                await userRepository.updateUser({ id: decoded.id }, {
                    mfaSecret: secret.base32,
                    mfaEnabled: true,
                    recoveryCode: hashedRecoveryCode,
                });
                const qrCode = await qrcode.toDataURL(secret.otpauth_url);
                res.json({
                    message: 'MFA enabled',
                    qrCode,
                    recoveryCode, // Display this to the user
                });
            } catch (err) {
                res.status(500).json({ error: 'Error enabling MFA' });
            }
        },
        verifyMFA: async (req, res) => {
            const { tempSessionId, token } = req.body;
            try {
                const tempSession = await temporarySessionRepository.findTemporarySession({ sessionId: tempSessionId });
                if (!tempSession) {
                    return res.status(400).json({ error: 'Invalid or expired session' });
                }
        
                const user = await userRepository.findUserById({ id: tempSession.userId });
                const verified = speakeasy.totp.verify({
                    secret: user.mfaSecret,
                    encoding: 'base32',
                    token,
                    window:1,
                });
        
                // Check if the token is correct. If it isn't, exit with status 400 and error
                if (!verified) {
                    return res.status(400).json({ error: 'Invalid MFA token' });
                }
        
                // Remove temporary session after successful MFA verification
                await temporarySessionRepository.deleteTemporarySession({ sessionId: tempSessionId });
        
                // Issue token 
                const accessToken = generateAccessToken(user);
                const refreshToken = await generateRefreshToken(user.id);
                // Set tokens as HTTP-only cookies
                res.cookie('accessToken', accessToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
                    sameSite: 'strict',
                    maxAge: 15 * 60 * 1000, // 15 minutes
                });
                res.cookie('refreshToken', refreshToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'strict',
                    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
                });
                res.json({ message: 'Login successful' });
            } catch (err) {
                res.status(500).json({ error: 'Error verifying MFA' });
            }
        },
        recoverMFA: async (req, res) => {
            const { email, recoveryCode } = req.body;
            try {
                const user = await userRepository.findUserByEmail({ email: email });
                if (!user) {
                    return res.status(404).json({error: 'User not found with that email address'})
                }
                if (!user || !user.recoveryCode) {
                    return res.status(404).json({ error: 'Recovery code not found or MFA not enabled' });
                }
        
                const isValid = await bcrypt.compare(recoveryCode, user.recoveryCode);
                if (!isValid) {
                    return res.status(401).json({ error: 'Invalid recovery code' });
                }
        
                // Disable MFA
                await userRepository.updateUser({ id: user.id }, { 
                    mfaEnabled: false, 
                    mfaSecret: null, 
                    recoveryCode: null 
                });
                
                res.json({ message: 'MFA has been removed from your account' });
            } catch (err) {
                res.status(500).json({ error: 'Error recovering account' });
            }
        },
        resetMFA: async (req, res) => {
            const { userId } = req.body;
            try {
                const user = await userRepository.updateUser({ id: userId }, {
                    mfaEnabled: false,
                    mfaSecret: null,
                    recoveryCode: null,
                });
                res.json({ message: 'MFA reset successfully', user });
            } catch (err) {
                res.status(500).json({ error: 'Error resetting MFA' });
            }
        },
        requestPasswordReset: async (req, res) => {
            const { email } = req.body;
            try {
                const user = await userRepository.findUserByEmail({ email: email });
                if (!user) return res.status(404).json({ error: 'No user found' });
        
                // Delete any existing tokens for this user
                await passwordResetTokenRepository.deleteManyFromUser({ userId: user.id });
        
                // Create token, store hashed, set expiration
                const token = crypto.randomBytes(32).toString('hex');
                const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
                await passwordResetTokenRepository.createPasswordResetToken({ 
                    userId: user.id, 
                    token: token,
                    expiresAt: expiresAt 
                });
            
                // Send email with reset link, e.g. https://yourapp.com/reset-password/:token
                // Include token as a URL param or query string
                await sendEmail(user.email, 'Password Reset', `Reset link: ${process.env.HOME_URL}/auth/reset-password/${token}`);
                res.json({ message: 'Reset link sent' });
            } catch (err) {
                res.status(500).json({ error: 'Request failed' });
            }
        },
        resetPassword: async (req, res) => {
            const { token, newPassword } = req.body;
            try {
                const resetToken = await passwordResetTokenRepository.findPasswordResetToken({ token: token });
                if (!resetToken || resetToken.expiresAt < new Date()) {
                    return res.status(400).json({ error: 'Invalid or expired reset token' });
                }
            
                // Update user password
                const hashedPassword = await bcrypt.hash(newPassword, 10);
                await userRepository.updateUser({id: resetToken.userId}, {
                    password: hashedPassword
                });
            
                // Remove token from DB
                await passwordResetTokenRepository.deletePasswordResetToken({ token: token });
            
                res.json({ message: 'Password reset successful' });
            } catch (err) {
                res.status(500).json({ error: 'Reset failed' });
            }
        },
    }

}