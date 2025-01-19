const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String },
    googleId: { type: String, unique: true, sparse: true },
    role: {type: String, enum: ['user', 'admin'], default: 'user'},
    mfaEnabled: { type: Boolean, default: false },
    mfaSecret: { type: String },
    recoveryCode: { type: String },
}, { timestamps: true });

module.exports = mongoose.model('User', UserSchema);