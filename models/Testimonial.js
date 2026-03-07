const mongoose = require('mongoose');

const testimonialSchema = new mongoose.Schema({
    authorName: { 
        type: String, 
        required: true 
    },
    content: { 
        type: String, 
        required: true 
    },
    mediaType: { 
        type: String, 
        enum: ['image', 'video', 'none'], 
        default: 'none' 
    },
    mediaUrl: { 
        type: String, 
        default: null 
    },
    isApproved: { 
        type: Boolean, 
        default: true // Set to false if users submit these and admin needs to approve
    },
    createdAt: { 
        type: Date, 
        default: Date.now 
    }
});

module.exports = mongoose.model('Testimonial', testimonialSchema);
