const mongoose = require('mongoose');

const helpIssueSchema = new mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    subject: { 
        type: String, 
        required: true 
    },
    summary: { 
        type: String, 
        required: true 
    },
    screenshotUrl: { 
        type: String 
    },
    status: { 
        type: String, 
        default: 'Pending', // 'Pending', 'Resolved'
        enum: ['Pending', 'Resolved'] 
    },
    date: { 
        type: Date, 
        default: Date.now 
    }
});

module.exports = mongoose.model('HelpIssue', helpIssueSchema);
