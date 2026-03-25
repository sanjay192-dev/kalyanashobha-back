const mongoose = require('mongoose');

const VendorSchema = new mongoose.Schema({
  vendorId: { type: String, unique: true }, 
  businessName: { type: String, required: true },
  email: { type: String, required: true }, // Added email field
  category: { type: String, required: true }, // Removed the enum array
  description: { type: String },
  contactNumber: { type: String, required: true },
  images: [{ type: String }], // Cloudinary URLs
  priceRange: { type: String },
  isApproved: { type: Boolean, default: false }, // Defaults to false for self-registration
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Vendor', VendorSchema);
