const mongoose = require('mongoose');

const InterestSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  
  // Workflow Status
  status: { 
    type: String, 
    enum: ['PendingPayment', 'PendingAdmin', 'PendingUser', 'Accepted', 'Rejected', 'Declined'], 
    default: 'PendingPayment' 
  },
  
  paymentId: { type: mongoose.Schema.Types.ObjectId, ref: 'PaymentInterest' },
  adminRejectionReason: { type: String },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Interest', InterestSchema);
