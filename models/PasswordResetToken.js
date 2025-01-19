const mongoose = require('mongoose');

const PasswordResetTokenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  token: String,
  expiresAt: Date
});

module.exports = mongoose.model('PasswordResetToken', PasswordResetTokenSchema);