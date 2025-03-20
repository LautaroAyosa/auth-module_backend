const mongoose = require('mongoose');

const emailVerificationToken = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'user' },
  newEmail: String,
  token: String,
  expiresAt: Date
});

module.exports = mongoose.model('emailVerificationToken', emailVerificationToken);