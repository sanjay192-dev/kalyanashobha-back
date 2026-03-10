// models/PendingMasterData.js
const mongoose = require('mongoose');

const pendingMasterDataSchema = new mongoose.Schema({
    category: { type: String, required: true }, // e.g., 'Community', 'SubCommunity', 'Country', 'Education'
    value: { type: String, required: true },    // The new string the user typed
    parentValue: { type: String },              // Only used if category is 'SubCommunity' (to know which Community it belongs to)
    status: { type: String, enum: ['Pending', 'Approved', 'Rejected'], default: 'Pending' },
    submittedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' } // Tracks who suggested it
}, { timestamps: true });

// Prevent duplicate pending requests for the same exact value
pendingMasterDataSchema.index({ category: 1, value: 1, parentValue: 1 }, { unique: true });

module.exports = mongoose.model('PendingMasterData', pendingMasterDataSchema);

