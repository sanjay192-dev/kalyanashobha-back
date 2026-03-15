// models/MasterData.js
const mongoose = require('mongoose');

const masterDataSchema = new mongoose.Schema({
    category: { type: String, required: true, index: true }, 
    name: { type: String, required: true },
    parentValue: { type: String, default: null, index: true }, // <-- ADDED: Links City to State, State to Country
    subItems: [{ type: String }],
    order: { type: Number, default: 0 }
}, { timestamps: true });

// Updated index to include parentValue so duplicate names in different parents are allowed
masterDataSchema.index({ category: 1, name: 1, parentValue: 1 }, { unique: true });
module.exports = mongoose.model('MasterData', masterDataSchema);
