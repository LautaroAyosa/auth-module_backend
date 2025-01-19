const mongoose = require('mongoose');

const TemporarySessionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' },
    sessionId: { type: String, required: true, unique: true },
    createdAt: { type: Date, default: Date.now, expires: 300 }, // Auto-delete after 5 minutes
});

module.exports = mongoose.model('TemporarySession', TemporarySessionSchema);