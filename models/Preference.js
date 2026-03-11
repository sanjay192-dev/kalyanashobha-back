const mongoose = require('mongoose');

const PreferenceSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  minAge: { type: Number },
  maxAge: { type: Number },
  minHeight: { type: Number },
  maxHeight: { type: Number },
  maritalStatus: { type: String },
  education: { type: String },
  community: { type: String },
  subCommunity: { type: String },
  occupation: { type: String },
  country: { type: String },
  state: { type: String },
  city: { type: String },
  motherTongue: { type: String },
  star: { type: String },
  pada: { type: String },
  diet: { type: String },
  complexion: { type: String }
}, { timestamps: true });

module.exports = mongoose.model('Preference', PreferenceSchema);
