const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  // --- A. Profile For ---
  profileFor: { type: String, required: true },

  // --- B. Gender ---
  gender: { type: String, enum: ['Male', 'Female'], required: true },

  // --- C. Personal Details ---
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  dob: { type: Date, required: true },

  // --- D. Religion & Community ---
  religion: { type: String, required: true },
  community: { type: String, required: true },
  country: { type: String, required: true },

  // --- E. Living Details ---
  state: { type: String, required: true },
  city: { type: String, required: true },
  subCommunity: { type: String },
  caste: { type: String },

  // --- F. Basic Information ---
  maritalStatus: { type: String, required: true },
  height: { type: Number }, 
  diet: { type: String, enum: ['Veg', 'Non-Veg', 'Eggetarian'] },

  // --- G. Education ---
  highestQualification: { type: String },
  collegeName: { type: String },

  // --- H. Work & Income ---
  annualIncome: { type: String }, 
  workType: { type: String, enum: ['Govt', 'Private', 'Business', 'Self-Employed'] },
  jobRole: { type: String },
  companyName: { type: String },

  // --- I. Contact Info & AUTH ---
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true }, // ADDED: For Login
  mobileNumber: { type: String, unique: true, required: true },
  isEmailVerified: { type: Boolean, default: false },
  // --- J. Photos ---
  photos: [{ type: String }],

  // --- K. Unique ID ---
  uniqueId: { type: String, unique: true },

  // --- L. Referral Tracking ---
  referredByAgentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Agent', default: null },
  referredByAgentName: { type: String, default: null },
  referralType: { type: String, enum: ['link', 'manual', 'none'], default: 'none' },

  // --- M. Access & Permissions ---
  isPaidMember: { type: Boolean, default: false },
  isApproved: { type: Boolean, default: false }, 
  isActive: { type: Boolean, default: true },   
  rejectionReason: { type: String },   

  fcmToken: { type: String },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', UserSchema);
