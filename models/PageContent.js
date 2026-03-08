const mongoose = require('mongoose');

const pageContentSchema = new mongoose.Schema({
    pageName: { 
        type: String, 
        required: true, 
        unique: true, 
        enum: ['terms', 'refund', 'about', 'faq'] // Added 'faq' to the allowed enum values
    },
    content: { 
        type: String, // You can store plain text or HTML here (from a Rich Text Editor)
        required: true 
    },
    lastUpdatedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Admin'
    }
}, { timestamps: true });

module.exports = mongoose.model('PageContent', pageContentSchema);
