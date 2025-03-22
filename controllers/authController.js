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
    const emailVerificationTokenRepository = repositories.emailVerificationTokenRepository;

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
        validateSession: async (req, res) => {
            const accessToken = req.cookies?.accessToken;
            if (!accessToken) {
                return res.status(401).json({ error: 'No access token provided'})
            }
            try {
                // Check if accessToken is valid
                const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
                const user = await userRepository.findUserById({id: decoded.id});
                res.status(200).json({ authenticated: true, user: { id: user.id, name: user.name, email: user.email, mfaEnabled: user.mfaEnabled, role: user.role } });
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
        
                const createdUser = await userRepository.createUser({ 
                    name: name, 
                    email: email, 
                    password: hashedPassword 
                });
                const user = {
                    name: createdUser.name,
                    email: createdUser.email,
                    googleId: createdUser.googleId,
                    role: createdUser.role,
                    mfaEnabled: createdUser.mfaEnabled,
                }
                res.status(201).json(user);
            } catch (err) {
                if (err.code === 11000 || err.parent?.code === '23505') {
                    return res.status(400).json({ 
                        error: 'Email already in use', 
                        details: err.message 
                    });
                }
                res.status(500).json({ error: 'Error registering user', details: err.message });
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
        
                res.status(200).json({ message: 'Login successful' });        
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
                res.status(200).json({ message: 'Logged out successfully' });
            } catch (err) {
                res.status(500).json({ error: 'Error logging out' });
            }
        },
        deleteUser: async (req, res) => {
            // Add:
            //  - User finding. Should only try to delete an user if it finds it. 
            //  - Role verification. Only admins should be able to delete users.
            const body = req.body;
            try {
                
                if (body.id) { await userRepository.deleteOneUser({ id: body.id }) }
                else if (body.email) { await userRepository.deleteOneUser({ email: body.email })}
                
                res.status(200).json({ message: 'Deleted User successfully'});
            } catch (err) {
                res.status(500).json({ error: 'There has been an error deleting the user: ', err })
            }
        },
        updateUser: async (req, res) => {
            try {
                const {name, email, password, confirmPassword} = req.body
                const { refreshToken } = req.cookies;
                if (!refreshToken) {
                    return res.status(401).json({ error: "Unauthorized: No refresh token provided"});
                }

                // Get user Id from refreshToken
                const {userId} = await refreshTokenRepository.findRefreshToken({token: refreshToken})
                if (!userId) {
                    return res.status(403).json({ error: "Forbidden: invalid refresh token"});
                }

                // Get refreshToken's account email
                const user = await userRepository.findUserById({id: userId})
                if (!user) {
                    return res.status(404).json({ error: "User not found"})
                }

                // Verify the account being updated is the same that requested the change.
                if (user.email !== email && email) {
                    // User is trying to change email → Send confirmation email
                    const token = crypto.randomBytes(32).toString("hex")
                    
                    // Get html email, replace links and send it.
                    // const emailContent = emailVerificationTemplate.replace("{{verification_link}}", `${process.env.HOME_URL}/dashboard/setting/verify-email/${token}`);
                    await sendEmail(user.email, "Verify Your Email Change", `Follow this link to accept the email change ${process.env.HOME_URL}/verify-email/${token}`);

                    // If emails is sent successfully, store the token in the db.
                    const expiresAt = new Date(Date.now() + 6 * 60 * 60 * 1000); // 6 hours
                    await emailVerificationTokenRepository.createToken({userId: userId, newEmail: email, token: token, expiresAt: expiresAt})
                    return res.status(200).json({ message: "Verification email sent. Please check your inbox to confirm email change."});
                }

                // If the user is updating the password, validate inputs
                let hashedPassword = passport // Keep existing password if not changing
                if (password) {
                    if (!confirmPassword) {
                        return res.status(400).json({error: "Confirm password is required when changing the password"})
                    }
                    if (password !== confirmPassword) {
                        return res.status(400).json({error: "Passwords do not match"})
                    }
                    hashedPassword = await bcrypt.hash(password, 10);
                }

                const updatedUser = await userRepository.updateUser({_id: userId}, {
                    ...(name && {name}), // Update name if provided
                    ...(password && {password: hashedPassword}) // Update password if provided
                });
                return res.status(200).json({
                    message: "Account updated successfully", 
                    user: {
                        name: updatedUser.name,
                        role: updatedUser.role,
                        mfaEnabled: updatedUser.mfaEnabled,
                    }})

            } catch (err) {
                console.error("Error updating user:", err)
                res.status(500).json({ error: 'Error updating your account' });
            }
        },
        updateEmail: async (req, res) => {
            try {
                const {token} = req.params;

                if (!token) {
                    res.status(400).json({error: "Invalid request: No token provided"});
                }
                // Find the email verification record
                const emailVerification = await emailVerificationTokenRepository.findToken({token});
                if (!emailVerification) {
                    return res.status(400).json({error: "Invalid or expired token"})
                }

                const {userId, newEmail} = emailVerification

                // Check if email is already in use
                const existingUser = await userRepository.findUserByEmail({email: newEmail});

                if (existingUser) {
                    return res.status(400).json({error: "Email is already in use"})
                }

                // Update user's email
                const newUser = await userRepository.updateUser({_id: userId}, {email: newEmail});
                
                if ( newUser.email === newEmail ) {
                    await emailVerificationTokenRepository.deleteToken({token});
                    return res.status(200).json({message: "Email updated successfully", email: newUser.email})
                    
                } else {
                    return res.status(400).json({error: "We coulnd't update your email" })
                }

            } catch (err) {
                console.error("Error updating account email", err)
                res.status(500).json({ error: "Error updating your account's email"})
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
                res.status(200).json({ message: 'Access token refreshed' });
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
        
                await userRepository.updateUser({ _id: decoded.id }, {
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
                res.status(200).json({ authenticated: true, user: {name: user.name, email: user.email, role: user.role, mfaEnabled: user.mfaEnabled}});
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
                await userRepository.updateUser({ _id: user.id }, { 
                    mfaEnabled: false, 
                    mfaSecret: null, 
                    recoveryCode: null 
                });
                
                res.status(200).json({ message: 'MFA has been removed from your account' });
            } catch (err) {
                res.status(500).json({ error: 'Error recovering account' });
            }
        },
        resetMFA: async (req, res) => {
            const { userId } = req.body;
            try {
                const user = await userRepository.updateUser({ _id: userId }, {
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
            try {
                const { email } = req.body;
                const user = await userRepository.findUserByEmail({ email: email });
                if (!user) return res.status(404).json({ error: 'No user found' });
                // Delete any existing tokens for this user
                await passwordResetTokenRepository.deleteManyFromUser({ userId: user.id });
                
                // Create token, store hashed, set expiration
                const token = crypto.randomBytes(32).toString('hex');
                const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
                await passwordResetTokenRepository.createPasswordResetToken({ 
                    token: token,
                    expiresAt: expiresAt,
                    userId: user.id,
                });
            
                // Send email with reset link, e.g. https://yourapp.com/authentication/reset-password/:token
                // Include token as a URL param or query string
                await sendEmail(user.email, 'Password Reset', `Reset link: ${process.env.HOME_URL}/authentication/reset-password/${token}`);
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
                await userRepository.updateUser({_id: resetToken.userId}, {
                    password: hashedPassword
                });
            
                // Remove token from DB
                await passwordResetTokenRepository.deletePasswordResetToken({ token: token });
            
                res.status(200).json({ message: 'Password reset successful' });
            } catch (err) {
                res.status(500).json({ error: 'Reset failed' });
            }
        },
    }

}