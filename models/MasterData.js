// models/MasterData.js
const mongoose = require('mongoose');

const masterDataSchema = new mongoose.Schema({
    category: { type: String, required: true, index: true }, 
    name: { type: String, required: true },
    subItems: [{ type: String }],
    order: { type: Number, default: 0 } // <-- ADD THIS FIELD
}, { timestamps: true });

masterDataSchema.index({ category: 1, name: 1 }, { unique: true });
module.exports = mongoose.model('MasterData', masterDataSchema);
