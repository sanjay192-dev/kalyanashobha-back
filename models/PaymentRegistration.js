const mongoose = require('mongoose');

const PaymentRegistrationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  
  // Manual Payment Details
  utrNumber: { type: String, required: true },
  screenshotUrl: { type: String, required: true },
  
  // Status
  status: { type: String, enum: ['PendingVerification', 'Success', 'Rejected'], default: 'PendingVerification' },
  adminNote: { type: String }, // Reason for rejection if any
  
  date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('PaymentRegistration', PaymentRegistrationSchema);
