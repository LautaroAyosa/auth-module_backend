const mongoose = require('mongoose');

const passwordResetTokenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'user' },
  token: String,
  expiresAt: Date
});

module.exports = mongoose.model('passwordResetToken', passwordResetTokenSchema);