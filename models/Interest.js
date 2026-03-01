const mongoose = require('mongoose');
const InterestSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  
  // Notice we removed paymentId completely!

  status: {
    type: String,
    enum: [
      'PendingAdminPhase1', // Step 2: User A sent, Admin needs to approve to send to B
      'PendingUser',        // Step 3: Sent to User B, waiting for their response
      'PendingAdminPhase2', // Step 4: User B accepted, Admin gets both contacts to finalize
      'Finalized',          // Admin successfully connected them offline
      'Declined',           // User B rejected the request
      'Rejected'            // Admin rejected the request at Phase 1 or 2
    ],
    default: 'PendingAdminPhase1'
  },
  date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Interest', InterestSchema);
