const mongoose = require('mongoose');

const PaymentInterestSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },

  // Manual Payment Details
  utrNumber: { type: String, required: true },
  screenshotUrl: { type: String, required: true },

  // Status
  status: { type: String, enum: ['PendingVerification', 'Success', 'Rejected'], default: 'PendingVerification' },
  adminNote: { type: String },

  date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('PaymentInterest', PaymentInterestSchema);
