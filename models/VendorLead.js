// models/VendorLead.js
const mongoose = require('mongoose');

const VendorLeadSchema = new mongoose.Schema({
    vendorId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Vendor', 
        required: true 
    },
    name: { type: String, required: true },
    phone: { type: String, required: true },
    email: { type: String },
    weddingDate: { type: String }, // Stored as string for flexibility (e.g., "Dec 2026")
    guestCount: { type: String },
    message: { type: String, required: true },
    status: { 
        type: String, 
        enum: ['New', 'Contacted', 'Forwarded', 'Closed'], 
        default: 'New' 
    },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('VendorLead', VendorLeadSchema);
