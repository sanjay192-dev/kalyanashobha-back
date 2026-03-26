// models/Settings.js
const mongoose = require('mongoose');

const SettingsSchema = new mongoose.Schema({
    maleRegistrationFee: { type: Number, default: 0 },
    femaleRegistrationFee: { type: Number, default: 0 },
    upiId: { type: String }, // Added dynamic UPI ID field
    lastUpdatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' }
}, { timestamps: true });

module.exports = mongoose.model('Settings', SettingsSchema);
