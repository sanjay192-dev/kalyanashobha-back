const mongoose = require('mongoose');

const masterDataSchema = new mongoose.Schema({
    category: { 
        type: String, 
        required: true, 
        index: true // Indexed because you will search by category a lot
        // e.g., 'State', 'Education', 'Occupation', 'Diet'
    }, 
    name: { 
        type: String, 
        required: true 
        // e.g., 'Andhra Pradesh', 'B.Tech / B.E.', 'Private Company'
    },
    subItems: [{ 
        type: String 
        // e.g., for State -> ['Chennai', 'Hyderabad']
        // e.g., for Education -> ['Computer Science', 'Mechanical'] (if needed, otherwise leave empty)
    }] 
}, { timestamps: true });

// Prevent duplicate names within the same category
masterDataSchema.index({ category: 1, name: 1 }, { unique: true });

module.exports = mongoose.model('MasterData', masterDataSchema);

