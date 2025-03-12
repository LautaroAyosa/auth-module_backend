const mongoose = require('mongoose');

const temporarySessionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'user' },
    sessionId: { type: String, required: true, unique: true },
    createdAt: { type: Date, default: Date.now, expires: 300 }, // Auto-delete after 5 minutes
});

module.exports = mongoose.model('temporarySession', temporarySessionSchema);