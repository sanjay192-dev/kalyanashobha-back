// models/CommunityModel.js
const mongoose = require('mongoose');

const CommunitySchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true, trim: true },
  subCommunities: [{ type: String, trim: true }]
});

module.exports = mongoose.model('Community', CommunitySchema);
