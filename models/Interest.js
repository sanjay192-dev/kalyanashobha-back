const mongoose = require('mongoose');

const InterestSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  paymentId: { type: mongoose.Schema.Types.ObjectId, ref: 'PaymentInterest' },

  status: {
    type: String,
    enum: [
      'PendingPaymentVerification',
      'PendingAdmin',
      'PendingUser',
      'Accepted',
      'Declined',
      'Rejected'
    ],
    default: 'PendingPaymentVerification'
  },

  date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Interest', InterestSchema);