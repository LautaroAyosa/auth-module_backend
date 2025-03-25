const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const speakeasy = require('speakeasy');
const crypto = require('crypto');
const qrcode = require('qrcode');
const sendEmail = require('../utils/sendEmail');
const { generateAccessToken, generateRefreshToken, setTokenCookies } = require('../utils/tokenUtils');
const handleError = require('../utils/errorHandler');

module.exports = (repositories) => {
    const { userRepository, refreshTokenRepository, temporarySessionRepository, passwordResetTokenRepository, emailVerificationTokenRepository } = repositories;

    return {
        validateSession: async (req, res) => {
            const user = req.user;
            if (!user) {
                return handleError(res, 401, 'No access token provided');
            }
            try {
                const userData = await userRepository.findUserById({ id: user.id }, ['name', 'email', 'role', 'mfaEnabled']);
                res.status(200).json({ authenticated: true, user: { id: userData.id, name: userData.name, email: userData.email, mfaEnabled: userData.mfaEnabled, role: userData.role } });
            } catch (err) {
                return handleError(res, 500, 'Error validating session');
            }
        },
        register: async (req, res) => {
            const { name, email, password } = req.body;
            try {
                const hashedPassword = await bcrypt.hash(password, 10);
                const createdUser = await userRepository.createUser({ name, email, password: hashedPassword });
                const user = { name: createdUser.name, email: createdUser.email, role: createdUser.role, mfaEnabled: createdUser.mfaEnabled };
                res.status(201).json(user);
            } catch (err) {
                if (err.code === 11000 || err.parent?.code === '23505') {
                    return handleError(res, 400, 'Email already in use');
                }
                return handleError(res, 500, 'Error registering user');
            }
        },
        login: async (req, res) => {
            const { email, password } = req.body;
            try {
                const user = await userRepository.findUserByEmail({ email }, ['id', 'email', 'role', 'mfaEnabled', 'password']);
                if (!user || !(await bcrypt.compare(password, user.password))) {
                    return handleError(res, 401, 'Invalid credentials');
                }
                if (user.mfaEnabled) {
                    const tempSessionId = crypto.randomBytes(16).toString('hex');
                    await temporarySessionRepository.createTemporarySession({ userId: user.id, sessionId: tempSessionId });
                    return res.status(200).json({ mfaRequired: true, tempSessionId, message: 'MFA verification required' });
                }
                const accessToken = generateAccessToken(user);
                const refreshToken = await generateRefreshToken(user.id, refreshTokenRepository);
                setTokenCookies(res, accessToken, refreshToken);
                res.status(200).json({ message: 'Login successful' });
            } catch (err) {
                return handleError(res, 500, 'Error logging in');
            }
        },
        logout: async (req, res) => {
            const { refreshToken } = req.cookies;
            try {
                await refreshTokenRepository.deleteRefreshToken({ token: refreshToken });
                res.clearCookie('accessToken');
                res.clearCookie('refreshToken');
                res.status(200).json({ message: 'Logged out successfully' });
            } catch (err) {
                return handleError(res, 500, 'Error logging out');
            }
        },
        deleteUser: async (req, res) => {
            const { email } = req.body;
            const user = req.user;
            try {
                const requestingUser = await userRepository.findUserById({ id: user.id }, ['email', 'role']);
                if (email !== requestingUser.email && requestingUser.role !== 'admin') {
                    return handleError(res, 403, 'Forbidden');
                }
                await userRepository.deleteOneUser({ email });
                res.status(200).json({ message: 'Deleted User successfully' });
            } catch (err) {
                return handleError(res, 500, 'Error deleting user');
            }
        },
        updateUser: async (req, res) => {
            const { name, email, password, confirmPassword } = req.body;
            const user = req.user;
            try {
                const existingUser = await userRepository.findUserById({ id: user.id }, ['email']);
                if (!existingUser) {
                    return handleError(res, 404, 'User not found');
                }
                if (existingUser.email !== email && email) {
                    const token = crypto.randomBytes(32).toString('hex');
                    await sendEmail(existingUser.email, 'Verify Your Email Change', `Follow this link to accept the email change ${process.env.HOME_URL}/verify-email/${token}`);
                    const expiresAt = new Date(Date.now() + 6 * 60 * 60 * 1000); // 6 hours
                    await emailVerificationTokenRepository.createToken({ userId: user.id, newEmail: email, token, expiresAt });
                    return res.status(200).json({ message: 'Verification email sent. Please check your inbox to confirm email change.' });
                }
                let hashedPassword = existingUser.password;
                if (password) {
                    if (!confirmPassword) {
                        return handleError(res, 400, 'Confirm password is required when changing the password');
                    }
                    if (password !== confirmPassword) {
                        return handleError(res, 400, 'Passwords do not match');
                    }
                    hashedPassword = await bcrypt.hash(password, 10);
                }
                const updatedUser = await userRepository.updateUser({ _id: user.id }, {
                    ...(name && { name }),
                    ...(password && { password: hashedPassword })
                });
                res.status(200).json({ message: 'Account updated successfully', user: { name: updatedUser.name, role: updatedUser.role, mfaEnabled: updatedUser.mfaEnabled } });
            } catch (err) {
                console.error('Error updating user:', err);
                return handleError(res, 500, 'Error updating your account');
            }
        },
        updateEmail: async (req, res) => {
            const { token } = req.params;
            if (!token) {
                return handleError(res, 400, 'Invalid request: No token provided');
            }
            try {
                const emailVerification = await emailVerificationTokenRepository.findToken({ token });
                if (!emailVerification) {
                    return handleError(res, 400, 'Invalid or expired token');
                }
                const { userId, newEmail } = emailVerification;
                const existingUser = await userRepository.findUserByEmail({ email: newEmail });
                if (existingUser) {
                    return handleError(res, 400, 'Email is already in use');
                }
                const newUser = await userRepository.updateUser({ _id: userId }, { email: newEmail });
                if (newUser.email === newEmail) {
                    await emailVerificationTokenRepository.deleteToken({ token });
                    res.status(200).json({ message: 'Email updated successfully', email: newUser.email });
                } else {
                    return handleError(res, 400, "We couldn't update your email");
                }
            } catch (err) {
                console.error('Error updating account email', err);
                return handleError(res, 500, "Error updating your account's email");
            }
        },
        updateRole: async (req, res) => {
            const { userId, newRole } = req.body;
            const user = req.user;
            try {
                if (!user || user.role !== 'admin') {
                    return handleError(res, 403, 'Forbidden');
                }
                const updatedUser = await userRepository.updateUser({ _id: userId }, { role: newRole });
                res.status(200).json({ message: 'Role updated successfully', user: { name: updatedUser.name, email: updatedUser.email, role: updatedUser.role } });
            } catch (err) {
                return handleError(res, 500, 'Error updating user role');
            }
        },
        refreshToken: async (req, res) => {
            const { refreshToken } = req.cookies;
            if (!refreshToken) {
                return handleError(res, 401, 'No refresh token provided');
            }
            try {
                const tokenDoc = await refreshTokenRepository.findRefreshToken({ token: refreshToken });
                if (!tokenDoc || tokenDoc.expiresAt < new Date()) {
                    return handleError(res, 401, 'Invalid or expired refresh token');
                }
                const user = await userRepository.findUserById({ id: tokenDoc.userId }, ['name', 'email', 'role']);
                if (!user) {
                    return handleError(res, 404, 'User not found');
                }
                const newAccessToken = generateAccessToken(user);
                setTokenCookies(res, newAccessToken, refreshToken);
                res.status(200).json({ message: 'Access token refreshed' });
            } catch (err) {
                return handleError(res, 500, 'Error refreshing token');
            }
        },
        googleAuth: async (req, res) => {
            try {
                passport.authenticate('google', { scope: ['profile', 'email'] });
            } catch (err) {
                return handleError(res, 500, 'Error with Google authentication');
            }
        },
        protectedRoute: (req, res) => {
            res.json({ message: 'Welcome to the protected admin route!' });
        },
        makeAdmin: async (req, res) => {
            const { id } = req.body;
            try {
                const user = await userRepository.updateUser({ id }, { role: 'admin' });
                if (!user) {
                    return handleError(res, 404, 'User not found');
                }
                res.json({ message: `User ${user.email} is now an admin`, user });
            } catch (err) {
                return handleError(res, 500, 'Error updating user role');
            }
        },
        enableMFA: async (req, res) => {
            const user = req.user;
            if (!user) {
                return handleError(res, 401, 'No access token provided');
            }
            try {
                const secret = speakeasy.generateSecret({ name: `${process.env.APP_NAME} (${user.email})` });
                const recoveryCode = crypto.randomBytes(16).toString('hex');
                const hashedRecoveryCode = await bcrypt.hash(recoveryCode, 10);
                await userRepository.updateUser({ _id: user.id }, { mfaSecret: secret.base32, mfaEnabled: true, recoveryCode: hashedRecoveryCode });
                const qrCode = await qrcode.toDataURL(secret.otpauth_url);
                res.json({ message: 'MFA enabled', qrCode, recoveryCode });
            } catch (err) {
                return handleError(res, 500, 'Error enabling MFA');
            }
        },
        verifyMFA: async (req, res) => {
            const { tempSessionId, token } = req.body;
            try {
                const tempSession = await temporarySessionRepository.findTemporarySession({ sessionId: tempSessionId });
                if (!tempSession) {
                    return handleError(res, 400, 'Invalid or expired session');
                }
                const user = await userRepository.findUserById({ id: tempSession.userId }, ['name', 'email', 'role', 'mfaEnabled', 'mfaSecret']);
                const verified = speakeasy.totp.verify({ secret: user.mfaSecret, encoding: 'base32', token, window: 1 });
                if (!verified) {
                    return handleError(res, 400, 'Invalid MFA token');
                }
                await temporarySessionRepository.deleteTemporarySession({ sessionId: tempSessionId });
                const accessToken = generateAccessToken(user);
                const refreshToken = await generateRefreshToken(user.id, refreshTokenRepository);
                setTokenCookies(res, accessToken, refreshToken);
                res.status(200).json({ authenticated: true, user: { name: user.name, email: user.email, role: user.role, mfaEnabled: user.mfaEnabled } });
            } catch (err) {
                return handleError(res, 500, 'Error verifying MFA');
            }
        },
        recoverMFA: async (req, res) => {
            const { email, recoveryCode } = req.body;
            try {
                const user = await userRepository.findUserByEmail({ email }, ['recoveryCode']);
                if (!user) {
                    return handleError(res, 404, 'User not found with that email address');
                }
                if (!user.recoveryCode) {
                    return handleError(res, 404, 'Recovery code not found or MFA not enabled');
                }
                const isValid = await bcrypt.compare(recoveryCode, user.recoveryCode);
                if (!isValid) {
                    return handleError(res, 401, 'Invalid recovery code');
                }
                await userRepository.updateUser({ _id: user.id }, { mfaEnabled: false, mfaSecret: null, recoveryCode: null });
                res.status(200).json({ message: 'MFA has been removed from your account' });
            } catch (err) {
                return handleError(res, 500, 'Error recovering account');
            }
        },
        resetMFA: async (req, res) => {
            const { userId } = req.body;
            try {
                const user = await userRepository.updateUser({ _id: userId }, { mfaEnabled: false, mfaSecret: null, recoveryCode: null });
                res.json({ message: 'MFA reset successfully', user });
            } catch (err) {
                return handleError(res, 500, 'Error resetting MFA');
            }
        },
        requestPasswordReset: async (req, res) => {
            const { email } = req.body;
            try {
                const user = await userRepository.findUserByEmail({ email });
                if (!user) {
                    return handleError(res, 404, 'No user found');
                }
                await passwordResetTokenRepository.deleteManyFromUser({ userId: user.id });
                const token = crypto.randomBytes(32).toString('hex');
                const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
                await passwordResetTokenRepository.createPasswordResetToken({ token, expiresAt, userId: user.id });
                await sendEmail(user.email, 'Password Reset', `Reset link: ${process.env.HOME_URL}/authentication/reset-password/${token}`);
                res.json({ message: 'Reset link sent' });
            } catch (err) {
                return handleError(res, 500, 'Request failed');
            }
        },
        resetPassword: async (req, res) => {
            const { token, newPassword } = req.body;
            try {
                const resetToken = await passwordResetTokenRepository.findPasswordResetToken({ token });
                if (!resetToken || resetToken.expiresAt < new Date()) {
                    return handleError(res, 400, 'Invalid or expired reset token');
                }
                const hashedPassword = await bcrypt.hash(newPassword, 10);
                await userRepository.updateUser({ _id: resetToken.userId }, { password: hashedPassword });
                await passwordResetTokenRepository.deletePasswordResetToken({ token });
                res.status(200).json({ message: 'Password reset successful' });
            } catch (err) {
                return handleError(res, 500, 'Reset failed');
            }
        },
        getAllUsers: async (req, res) => {
            const user = req.user;
            try {
                if (!user || user.role !== 'admin') {
                    return handleError(res, 403, 'Forbidden');
                }
                const users = await userRepository.findAllUsers(['name', 'email', 'role', 'mfaEnabled']);
                res.status(200).json(users);
            } catch (err) {
                return handleError(res, 500, 'Error getting users');
            }
        },
        getUserById: async (req, res) => {
            const { id } = req.params;
            try {
                const user = await userRepository.findUserById({ id: id }, ['name', 'email', 'role', 'mfaEnabled']);
                if (!user) return handleError(res, 404, 'No user found');
                res.status(200).json(user);
            } catch (err) {
                return handleError(res, 500, 'Error getting user');
            }
        }
    };
};