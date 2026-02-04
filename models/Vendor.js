const mongoose = require('mongoose');

const VendorSchema = new mongoose.Schema({
  businessName: { type: String, required: true },
  category: { 
    type: String, 
    enum: ['Catering', 'Wedding halls', 'Photography', 'Decoration', 'Mehendi artists', 'Makeup', 'Event management', 'Travel', 'Pandit'],
    required: true 
  },
  description: { type: String },
  contactNumber: { type: String, required: true },
  images: [{ type: String }], // Cloudinary URLs
  priceRange: { type: String },
  isApproved: { type: Boolean, default: false }, // Admin must approve
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Vendor', VendorSchema);
