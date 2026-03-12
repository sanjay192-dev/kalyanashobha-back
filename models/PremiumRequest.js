const mongoose = require('mongoose');

const PremiumRequestSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    status: { type: String, enum: ['Pending', 'Contacted', 'Resolved'], default: 'Pending' },
    requestDate: { type: Date, default: Date.now }
});

module.exports = mongoose.model('PremiumRequest', PremiumRequestSchema);
