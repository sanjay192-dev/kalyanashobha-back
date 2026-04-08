
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('cloudinary').v2;
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const MasterData = require('./models/MasterData');
const Otp = require('./models/Otp');
const PendingMasterData = require('./models/PendingMasterData');
const Testimonial = require('./models/Testimonial');
const Preference = require('./models/Preference');
const PremiumRequest = require('./models/PremiumRequest');
const Settings = require('./models/Settings');

// ---------------- MODELS ----------------
const User = require('./models/User');
const Agent = require('./models/Agent');
const Vendor = require('./models/Vendor');
const Interest = require('./models/Interest');
const PaymentRegistration = require('./models/PaymentRegistration');
const PaymentInterest = require('./models/PaymentInterest');
const Admin = require('./models/Admin');
const Community = require('./models/CommunityModel');

const PageContent = require('./models/PageContent');

const HelpIssue = require('./models/HelpIssue');
const VendorLead = require('./models/VendorLead');

const app = express();
// Allow all headers and origins to fix the browser blocking issue
app.use(cors({
    origin: "*", 
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: "*" 
}));

app.use(express.json({ limit: '50mb' })); 
app.use(express.urlencoded({ limit: '50mb', extended: true }));


let isConnected = false; // Track connection status


const connectDB = async () => {
    // 1. If already connected, use existing connection
    if (mongoose.connection.readyState >= 1) {
        return;
    }

    // 2. If not, connect now
    try {
        await mongoose.connect(process.env.MONGO_URI, {
            dbName: "kalyanashobha", 
            serverSelectionTimeoutMS: 5000, 
            socketTimeoutMS: 45000, 
            
            // --- ADD THESE TWO LINES ---
            maxPoolSize: 10, // Restricts each Vercel instance to 10 connections instead of 100
            minPoolSize: 1   // Keeps at least 1 connection warm per instance
        });
        isConnected = true;
        console.log("MongoDB Connected (New Connection)");
    } catch (error) {
        console.error("MongoDB Connection Failed:", error);
    }
};




// 3. MIDDLEWARE: Ensure DB is connected BEFORE every request
app.use(async (req, res, next) => {
    await connectDB();
    next();
});







// ---------------- CLOUDINARY CONFIG ----------------
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Storage Configs
// ---------------- CLOUDINARY CONFIG ----------------

// Update the profileStorage configuration
const profileStorage = new CloudinaryStorage({
    cloudinary,
    params: { 
        folder: "matrimony_users", 
        allowed_formats: ["jpg", "jpeg", "png", "webp"], // Added webp
        transformation: [
            { width: 800, height: 800, crop: "limit" },
            { quality: "auto:eco", fetch_format: "auto" } // 'eco' forces aggressive KB compression
        ] 
    }
});
const uploadProfile = multer({ storage: profileStorage });


const paymentStorage = new CloudinaryStorage({
    cloudinary,
    params: { folder: "matrimony_payments", allowed_formats: ["jpg", "jpeg", "png"], transformation: [{ width: 1000, crop: "limit" }, { quality: "auto:low" }] }
});
const uploadPayment = multer({ storage: paymentStorage });

const vendorStorage = new CloudinaryStorage({
    cloudinary,
    params: { folder: "matrimony_vendors", allowed_formats: ["jpg", "jpeg", "png"] }
});
const uploadVendor = multer({ storage: vendorStorage });


// New Storage for Signatures
const signatureStorage = new CloudinaryStorage({
    cloudinary,
    params: { 
        folder: "matrimony_signatures", 
        allowed_formats: ["png", "jpg", "jpeg"] 
    }
});
const uploadSignature = multer({ storage: signatureStorage });
const issueStorage = new CloudinaryStorage({
    cloudinary,
    params: { 
        folder: "matrimony_issues", 
        allowed_formats: ["jpg", "jpeg", "png"] 
    }
});
const uploadIssue = multer({ storage: issueStorage });
// New Storage for Testimonials (Supports Images and Videos)
const testimonialStorage = new CloudinaryStorage({
    cloudinary,
    params: {
        folder: "matrimony_testimonials",
        resource_type: "auto", // This is the magic word that allows both images AND videos!
        allowed_formats: ["jpg", "jpeg", "png", "webp", "mp4", "mov", "avi"]
    }
});
const uploadTestimonial = multer({ storage: testimonialStorage });

const EMAIL_USER = "kalyanashobhamatrimony@gmail.com";



// ---------------- EMAIL SYSTEM (PROFESSIONAL - HOSTINGER) ----------------
const transporter = nodemailer.createTransport({
  host: "smtp.hostinger.com",
  port: 465,               // use 465 for secure SSL
  secure: true,            // true for port 465
  auth: {
    user: "info@kalyanashobha.in",   // your domain email
    pass: "Ksm@2026"         // Hostinger email password
  }
});


// Professional HTML Template Generator
const generateEmailTemplate = (title, bodyContent) => {
    return `
     <!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
</head>

<body style="margin:0; padding:0; background:#f5f5f5; font-family:Arial, Helvetica, sans-serif;">

  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f5f5f5; padding:20px 0;">
    <tr>
      <td>

        <!-- MAIN CARD -->
        <table align="center" cellpadding="0" cellspacing="0" width="600"
               style="background:#ffffff; border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,0.08); border:1px solid #e6e6e6;">
          
          <!-- LOGO -->
          <tr>
            <td align="center" style="padding:25px 20px; border-bottom:1px solid #eeeeee;">
              <img src="https://res.cloudinary.com/dppiuypop/image/upload/v1772548363/uploads/r94zgmrjfek4kucd6lhf.png"
                   alt="KalyanaShobha Logo"
                   style="width:180px; max-width:70%; height:auto; display:block;">
            </td>
          </tr>

          <!-- CONTENT -->
          <tr>
            <td style="padding:30px 40px; color:#333333; line-height:1.7; font-size:15px;">
              
              <h2 style="margin:0 0 15px 0; font-size:20px; color:#D32F2F; 
                         border-bottom:2px solid #FFC107; display:inline-block; padding-bottom:5px;">
                ${title}
              </h2>

              <div style="margin-top:15px; font-size:15px; color:#444444;">
                ${bodyContent}
              </div>

              <p style="margin-top:35px; margin-bottom:0; font-size:15px;">
                Sincerely,<br>
                <strong>The KalyanaShobha Team</strong>
              </p>

            </td>
          </tr>

          <!-- FOOTER -->
          <tr>
            <td style="background:#fafafa; text-align:center; padding:15px; 
                       font-size:12px; color:#888888; border-top:1px solid #e6e6e6;">
              <p style="margin:0;">This is an automated message. Please do not reply.</p>
              <p style="margin:3px 0 0 0;">&copy; ${new Date().getFullYear()} KalyanaShobha Matrimony. All rights reserved.</p>
            </td>
          </tr>

        </table>

      </td>
    </tr>
  </table>

</body>
</html>

    `;
};






async function sendMail({ to, subject, html, fromEmail }) {
    try {
        // We set a smart default: if no fromEmail is passed, it uses support@
        const sender = fromEmail || `"KalyanaShobha Support" <support@kalyanashobha.in>`;

        await transporter.sendMail({
            from: sender, 
            to, 
            subject,
            html 
        });
        return true;
    } catch (err) {
        console.error("MAIL ERROR:", err);
        return false;
    }
}







// ---------------- INDIA STATE CODES ----------------

const stateCodeMap = {
    "andhra pradesh": "AP",
    "arunachal pradesh": "AR",
    "assam": "AS",
    "bihar": "BR",
    "chhattisgarh": "CG",
    "goa": "GA",
    "gujarat": "GJ",
    "haryana": "HR",
    "himachal pradesh": "HP",
    "jharkhand": "JH",
    "karnataka": "KA",
    "kerala": "KL",
    "madhya pradesh": "MP",
    "maharashtra": "MH",
    "manipur": "MN",
    "meghalaya": "ML",
    "mizoram": "MZ",
    "nagaland": "NL",
    "odisha": "OD",
    "punjab": "PB",
    "rajasthan": "RJ",
    "sikkim": "SK",
    "tamil nadu": "TN",
    "telangana": "TG",
    "tripura": "TR",
    "uttar pradesh": "UP",
    "uttarakhand": "UK",
    "west bengal": "WB",

    // Union Territories
    "andaman and nicobar islands": "AN",
    "chandigarh": "CH",
    "dadra and nagar haveli": "DN",
    "daman and diu": "DD",
    "delhi": "DL",
    "jammu and kashmir": "JK",
    "ladakh": "LA",
    "puducherry": "PY"
};


// ---------------- USER ID GENERATOR ----------------

async function generateUserId(state) {
    if (!state) state = "India";

    // Convert to lowercase for lookup
    const key = state.toLowerCase().trim();

    // Get prefix safely
    let prefix = stateCodeMap[key] || "IN";

    // Find last user with this prefix
    const lastUser = await User.findOne({
        uniqueId: { $regex: `^${prefix}-` }
    }).sort({ uniqueId: -1 });

    let nextNumber = 1;

    if (lastUser) {
        const lastNum = parseInt(lastUser.uniqueId.split("-")[1]);
        nextNumber = lastNum + 1;
    }

    return `${prefix}-${String(nextNumber).padStart(5, "0")}`;
}
// ---------------- MIDDLEWARE: SECURITY ----------------

const verifyAdmin = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ success: false, message: "No token provided" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || "fallback_secret_key");
        if (decoded.role && (decoded.role === 'SuperAdmin' || decoded.role === 'Moderator')) {
            req.adminId = decoded.id;
            next();
        } else {
            return res.status(403).json({ success: false, message: "Not an Admin" });
        }
    } catch (err) {
        return res.status(401).json({ success: false, message: "Unauthorized" });
    }
};

const verifyUser = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ success: false, message: "No token provided" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || "fallback_secret_key");
        req.userId = decoded.id;
        next();
    } catch (err) {
        return res.status(401).json({ success: false, message: "Unauthorized" });
    }
};


const verifyAgent = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ success: false, message: "No token provided" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || "fallback_secret_key");
        // Check if the token belongs to an Agent (you might want to add a role in the token payload)
        // For now, we assume if it decodes and has an ID, we check the Agent collection
        req.agentId = decoded.id;
        next();
    } catch (err) {
        return res.status(401).json({ success: false, message: "Unauthorized Agent" });
    }
};

// ---------------- VENDOR ID GENERATOR ----------------
async function generateVendorId() {
    const prefix = "VND";

    // Find last vendor with this prefix
    const lastVendor = await Vendor.findOne({
        vendorId: { $regex: `^${prefix}-` }
    }).sort({ vendorId: -1 });

    let nextNumber = 1;

    if (lastVendor && lastVendor.vendorId) {
        const lastNum = parseInt(lastVendor.vendorId.split("-")[1]);
        if (!isNaN(lastNum)) {
            nextNumber = lastNum + 1;
        }
    }

    // Pad with 4 zeros (e.g., VND-0001)
    return `${prefix}-${String(nextNumber).padStart(4, "0")}`;
}



app.get("/api/agent/users/interests", verifyAgent, async (req, res) => {
    try {
        // 1. Get the IDs of all users referred by this agent
        const myUsers = await User.find({ referredByAgentId: req.agentId }).select('_id');
        const userIds = myUsers.map(u => u._id);

        if (userIds.length === 0) {
            return res.json({ success: true, count: 0, data: [] });
        }

        // 2. Find all interests where the sender OR receiver is one of the agent's users
        const interests = await Interest.find({
            $or: [
                { senderId: { $in: userIds } },
                { receiverId: { $in: userIds } }
            ]
        })
        .populate('senderId', 'firstName lastName uniqueId')
        .populate('receiverId', 'firstName lastName uniqueId')
        .sort({ date: -1 }); // Newest first

        // 3. Format the data to make it easy for the frontend to display
        const formattedInterests = interests.map(interest => {
            
            // Determine if the agent's user sent this request or received it
            const isSenderMyUser = userIds.some(id => 
                id.toString() === interest.senderId._id.toString()
            );

            return {
                interestId: interest._id,
                direction: isSenderMyUser ? "Sent" : "Received", // Did the agent's client send or receive this?
                myClient: isSenderMyUser ? interest.senderId : interest.receiverId,
                matchProfile: isSenderMyUser ? interest.receiverId : interest.senderId,
                status: interest.status,
                date: interest.date
            };
        });

        res.json({ success: true, count: formattedInterests.length, data: formattedInterests });

    } catch (e) {
        console.error("Agent Interests Error:", e);
        res.status(500).json({ success: false, message: "Server Error fetching interests" });
    }
});


// ====================================================================
// VENDORS (USER FACING)
// ====================================================================

// Get all approved vendors for users
app.get("/api/user/vendors",  async (req, res) => {
    try {
        // Fetch only vendors that have been approved by the admin
        // Sort by 'createdAt: -1' to show the newest vendors first
        const vendors = await Vendor.find({ isApproved: true }).sort({ createdAt: -1 });
        
        res.json({ 
            success: true, 
            count: vendors.length, 
            vendors 
        });

    } catch (error) {
        console.error("Fetch Vendors Error:", error);
        res.status(500).json({ success: false, message: "Server Error fetching vendors" });
    }
});



// ====================================================================
// H. AGENT AUTHENTICATION (Login with OTP)
// ====================================================================

// 1. Agent Login Init 
app.post("/api/agent/auth/login-init", async (req, res) => {
    try {
        const { email, password } = req.body;

        const agent = await Agent.findOne({ email, isActive: true });
        if (!agent) return res.status(404).json({ success: false, message: "Agent not found or inactive" });

        const isMatch = await bcrypt.compare(password, agent.password);
        if (!isMatch) return res.status(400).json({ success: false, message: "Invalid credentials" });

        // Generate OTP and save to MongoDB
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        
        await Otp.create({ email, otp: otpCode });

        const emailContent = generateEmailTemplate(
            "Agent Dashboard Access",
            `<p>Hello ${agent.name},</p>
             <p>Your OTP for Agent Dashboard login is:</p>
             <h2 style="color: #2c3e50; letter-spacing: 5px;">${otpCode}</h2>`
        );
        await sendMail({ 
    to: email, 
    subject: "Your Login OTP", 
    html: emailContent,
    fromEmail: `"KalyanaShobha Security" <noreply@kalyanashobha.in>`
});

        res.json({ success: true, message: "OTP sent to email" });

    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// 2. Agent Login Verify
app.post("/api/agent/auth/login-verify", async (req, res) => {
    try {
        const { email, otp } = req.body;

        const cleanOtp = String(otp).trim();
const otpRecord = await Otp.findOne({ email, otp: cleanOtp });
        

        if (otpRecord) {
            const agent = await Agent.findOne({ email });
            
            // Delete OTP after successful use
            await Otp.deleteOne({ _id: otpRecord._id });

            const token = jwt.sign(
                { id: agent._id, role: 'Agent' }, 
                process.env.JWT_SECRET || "fallback_secret_key", 
                { expiresIn: "1d" }
            );

            res.json({ 
                success: true, 
                token, 
                agent: {
                    id: agent._id,
                    name: agent.name,
                    email: agent.email,
                    mobile: agent.mobile,
                    agentCode: agent.agentCode
                }
            });
        } else {
            res.status(400).json({ success: false, message: "Invalid or Expired OTP" });
        }
    } catch (e) {
        res.status(500).json({ success: false, message: "Server Error" });
    }
});



// ====================================================================
// A. ADMIN AUTHENTICATION (UPDATED: With OTP)
// ====================================================================

app.post("/api/admin/seed", async (req, res) => {
    try {
        // 1. Define the admin email in one place to avoid mismatch
        const adminEmail = "adepusanjay444@gmail.com"; 

        // 2. Check for THIS email
        const existingAdmin = await Admin.findOne({ email: adminEmail });
        if (existingAdmin) {
            return res.status(400).json({ success: false, message: "Admin already exists" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash("admin123", salt);

        // 3. Create using the SAME email
        const admin = new Admin({
            username: "SuperAdmin", 
            email: adminEmail,
            password: hashedPassword, 
            role: "SuperAdmin"
        });
        
        await admin.save();
        res.json({ success: true, message: "Admin Created Successfully" });

    } catch (e) { 
        res.status(500).json({ success: false, message: e.message }); 
    }
});

// --- STEP 1: Validate Password & Send OTP ---
app.post("/api/admin/auth/login-init", async (req, res) => {
    try {
        const { email, password } = req.body;

        const admin = await Admin.findOne({ email });
        if (!admin) return res.status(404).json({ success: false, message: "Admin not found" });

        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) return res.status(400).json({ success: false, message: "Invalid credentials" });

        // Generate OTP and save to MongoDB
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        
        await Otp.create({ email, otp: otpCode });

        const emailContent = generateEmailTemplate(
            "Admin Dashboard Access",
            `<p>A login attempt was made for the Admin Panel.</p>
             <p>Your Verification Code is:</p>
             <h2 style="color: #c0392b; letter-spacing: 5px; font-weight: bold;">${otpCode}</h2>
             <p>This code is valid for 5 minutes. If this wasn't you, please change your password immediately.</p>`
        );

        await sendMail({ 
    to: email, 
    subject: "Your Login OTP", 
    html: emailContent,
    fromEmail: `"KalyanaShobha Security" <noreply@kalyanashobha.in>`
});

        res.json({ success: true, message: "OTP sent to registered admin email." });

    } catch (e) { 
        console.error(e);
        res.status(500).json({ success: false, message: "Server Error" }); 
    }
});


// --- STEP 2: Verify OTP & Issue Token ---
app.post("/api/admin/auth/login-verify", async (req, res) => {
    try {
        const { email, otp } = req.body;
        const cleanOtp = String(otp).trim();
const otpRecord = await Otp.findOne({ email, otp: cleanOtp });

        if (otpRecord) {
            const admin = await Admin.findOne({ email });
            await Otp.deleteOne({ _id: otpRecord._id }); 

            const token = jwt.sign(
                { id: admin._id, role: admin.role }, 
                process.env.JWT_SECRET || "fallback_secret_key", 
                { expiresIn: "1d" }
            );

            res.json({ 
                success: true, 
                token, 
                // This is the important part! Sending permissions back.
                admin: { 
                    username: admin.username, 
                    email: admin.email, 
                    role: admin.role,
                    permissions: admin.permissions 
                } 
            });
        } else {
            res.status(400).json({ success: false, message: "Invalid or Expired OTP" });
        }
    } catch (e) { 
        res.status(500).json({ success: false, message: "Server Error" }); 
    }
});



app.post("/api/admin/change-password", verifyAdmin, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        const admin = await Admin.findById(req.adminId);
        const isMatch = await bcrypt.compare(oldPassword, admin.password);
        if (!isMatch) return res.status(400).json({ success: false, message: "Old password incorrect" });

        const salt = await bcrypt.genSalt(10);
        admin.password = await bcrypt.hash(newPassword, salt);
        await admin.save();
        res.json({ success: true, message: "Password updated" });
    } catch (e) { res.status(500).json({ success: false }); }
});


// 1. Utility function to prevent regex crashes
const escapeRegExp = (string) => {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
};

// 2. The targeted, concurrent helper function
const checkAndStageNewMasterData = async (userId, data) => {
    const checkPromises = [];

    // --- 1. CAPTURE EXACT CATEGORIES WITH PARENTS ---
    const standardCategories = [
        { category: 'Country', value: data.country, parentValue: null },
        { category: 'State', value: data.state, parentValue: data.country }, // State belongs to Country
        { category: 'City', value: data.city, parentValue: data.state },     // City belongs to State
        { category: 'Education', value: data.highestQualification, parentValue: null },
        { category: 'Designation', value: data.jobRole, parentValue: null }
        // Gothra has been successfully removed from staging
    ];

    for (const item of standardCategories) {
        if (!item.value || item.value === 'null' || item.value === 'undefined' || item.value.trim() === '') {
            continue;
        }

        const val = item.value.trim();
        const safeRegex = escapeRegExp(val);

        // Build query to check if it exists (include parent if applicable)
        let query = { category: item.category, name: new RegExp(`^${safeRegex}$`, 'i') };
        if (item.parentValue) {
            query.parentValue = new RegExp(`^${escapeRegExp(item.parentValue.trim())}$`, 'i');
        } else {
            query.parentValue = null;
        }

        // Process each field concurrently
        const promise = MasterData.findOne(query)
            .then(async (exists) => {
                if (!exists) {
                    await PendingMasterData.updateOne(
                        { category: item.category, value: val, parentValue: item.parentValue ? item.parentValue.trim() : null },
                        { $setOnInsert: { status: 'Pending', submittedBy: userId } },
                        { upsert: true }
                    );
                }
            })
            .catch(err => console.error(`Failed to stage ${item.category}:`, err.message));

        checkPromises.push(promise);
    }

    // --- 2. COMMUNITY & SUB-COMMUNITY ---
    if (data.community && data.community !== 'null' && data.community !== 'undefined' && data.community.trim() !== '') {
        const commVal = data.community.trim();
        const safeCommRegex = escapeRegExp(commVal);

        const commPromise = Community.findOne({ name: new RegExp(`^${safeCommRegex}$`, 'i') })
            .then(async (commExists) => {
                // Check Community
                if (!commExists) {
                    await PendingMasterData.updateOne(
                        { category: 'Community', value: commVal },
                        { $setOnInsert: { status: 'Pending', submittedBy: userId } },
                        { upsert: true }
                    );
                }

                // Check SubCommunity
                if (data.subCommunity && data.subCommunity !== 'null' && data.subCommunity !== 'undefined' && data.subCommunity.trim() !== '') {
                    const subVal = data.subCommunity.trim();
                    let subExists = false;

                    if (commExists && commExists.subCommunities) {
                        subExists = commExists.subCommunities.some(sub => sub.toLowerCase() === subVal.toLowerCase());
                    }

                    if (!subExists) {
                        await PendingMasterData.updateOne(
                            { category: 'SubCommunity', value: subVal, parentValue: commVal },
                            { $setOnInsert: { status: 'Pending', submittedBy: userId } },
                            { upsert: true }
                        );
                    }
                }
            })
            .catch(err => console.error(`Failed to stage Community data:`, err.message));

        checkPromises.push(commPromise);
    }

    // --- 3. EXECUTE ALL AT ONCE ---
    await Promise.allSettled(checkPromises);
};

                


// 3. REGISTER ROUTE (Updated to await the master data check)

app.post("/api/auth/register", uploadSignature.single('digitalSignature'), async (req, res) => {
    try {
        const data = req.body;

        // --- STEP 1: VALIDATION ---
        if (!req.file) {
            return res.status(400).json({ 
                success: false, 
                message: "Digital Signature file is required." 
            });
        }
        const signatureUrl = req.file.path; 

        if (!data.password) {
            return res.status(400).json({ success: false, message: "Password is required" });
        }

        const existingUser = await User.findOne({ email: data.email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: "User already exists" });
        }

        // --- STEP 2: PREPARE USER DATA ---
        const uniqueId = await generateUserId(data.state);
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(data.password, salt);

        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        // Create User Instance
        const user = new User({ 
            ...data, 
            password: hashedPassword, 
            uniqueId, 
            photos: [],
            isEmailVerified: false, 
            isActive: true, 
            digitalSignature: signatureUrl, 
            termsAcceptedAt: new Date(),
            termsAcceptedIP: clientIp
        });

        // --- STEP 3: SAVE TO DB ---
        await user.save();

        // --- NEW: VERCEL FIX - Added 'await' so the server doesn't kill the process early ---
        await checkAndStageNewMasterData(user._id, data);

        // --- STEP 4: PREPARE EMAILS ---
        const userWelcomeContent = generateEmailTemplate(
            "Welcome to KalyanaShobha!",
            `<p>Dear <strong>${user.firstName} ${user.lastName}</strong>,</p>
             <p>Thank you for registering with us. Your profile has been created successfully.</p>
             <p><strong>Your Profile ID:</strong> ${user.uniqueId}</p>
             <p>You can now log in using your email and password to update your profile and upload photos.</p>
             <div style="text-align: center; margin: 20px 0; padding: 10px; background-color: #f9f9f9; border-radius: 5px;">
                <p style="color: #555; font-size: 13px;">(Note: For security, you will receive an OTP every time you log in.)</p>
             </div>`
        );

        const adminAlertContent = generateEmailTemplate(
            "New User Registration",
            `<p>A new user has just registered on the platform.</p>
             <table style="width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px;">
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd; width: 40%; color: #666;"><strong>Name:</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;">${user.firstName} ${user.lastName}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Profile ID:</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>${user.uniqueId}</strong></td>
                </tr>
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Email:</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;">${user.email}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Mobile:</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;">${user.mobileNumber}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Location:</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;">${user.city}, ${user.state}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Gender:</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;">${user.gender}</td>
                </tr>
             </table>
             <div style="margin-top: 20px; text-align: center;">
                <a href="https://kalyanashobha.in/admin" style="background-color: #2c3e50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; font-size: 14px;">Go to Admin Dashboard</a>
             </div>`
        );

        // --- STEP 5: SEND EMAILS ---
        const sendUserMail = sendMail({ 
            to: user.email, 
            subject: "Welcome to KalyanaShobha Matrimony", 
            html: userWelcomeContent 
        });

        const sendAdminMail = sendMail({ 
            to: EMAIL_USER, 
            subject: `New User: ${user.uniqueId} (${user.firstName})`, 
            html: adminAlertContent 
        });

        const emailPromises = [sendUserMail, sendAdminMail];

        if (data.referredByAgentId) {
            try {
                const agent = await Agent.findById(data.referredByAgentId);
                if (agent) {
                    const agentAlertContent = generateEmailTemplate(
                        "New Referral Registration",
                        `<p>Dear ${agent.name},</p>
                         <p>Great news! A new user has just registered using your referral link.</p>
                         <p><strong>User Name:</strong> ${user.firstName} ${user.lastName}</p>
                         <p><strong>Profile ID:</strong> ${user.uniqueId}</p>
                         <p>This user is now tracked under your agent dashboard.</p>
                         <div style="margin-top: 20px; text-align: center;">
                            <a href="https://kalyanashobha-agent.vercel.app" style="background-color: #2c3e50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; font-size: 14px;">Go to Agent Dashboard</a>
                         </div>`
                    );

                    const sendAgentMail = sendMail({ 
                        to: agent.email, 
                        subject: `New Referral Joined: ${user.firstName}`, 
                        html: agentAlertContent 
                    });

                    emailPromises.push(sendAgentMail);
                }
            } catch (agentErr) {
                console.error("Failed to fetch agent for referral email:", agentErr);
            }
        }

        try {
            await Promise.all(emailPromises);
            console.log("Registration emails sent successfully.");
        } catch (emailError) {
            console.error("Email Sending Failed:", emailError);
        }

        // --- STEP 6: RESPONSE ---
        res.json({ 
            success: true, 
            message: "Registration successful! Please login to continue.",
            email: user.email,
            uniqueId: user.uniqueId
        });

    } catch (e) { 
        console.error("Register Error:", e);
        res.status(500).json({ success: false, message: e.message }); 
    }
});
                        

// ======================== FORGOT PASSWORD (SEND OTP) =========================
// ======================== FORGOT PASSWORD (SEND OTP) =========================
app.post("/api/auth/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, message: "Email not found" });
        }

        // Generate OTP & Save to MongoDB
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        await Otp.deleteMany({ email });
        await Otp.create({ email, otp: otpCode });

        // FIXED: Changed variable name to emailContent so it matches below
        const emailContent = generateEmailTemplate(
            "Password Reset OTP",
            `<p>Your OTP for resetting password is:</p>
             <h2 style="letter-spacing: 3px; color:#2c3e50;">${otpCode}</h2>
             <p>This OTP is valid for <strong>5 minutes</strong>.</p>`
        );

        await sendMail({ 
            to: email, 
            subject: "Your Password Reset OTP", 
            html: emailContent, // Now this matches perfectly
            fromEmail: `"KalyanaShobha Security" <noreply@kalyanashobha.in>`
        });

        res.json({ success: true, message: "OTP sent to your registered email." });

    } catch (err) {
        console.error("Forgot Password Error:", err);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});


// ======================== VERIFY OTP =========================
app.post("/api/auth/verify-otp", async (req, res) => {
    try {
        const { email, otp } = req.body;

        const otpRecord = await Otp.findOne({ email, otp });

        if (!otpRecord) {
            return res.status(400).json({ success: false, message: "Invalid or Expired OTP" });
        }

        // OTP matched - update the record to mark it as verified
        otpRecord.otp = "VERIFIED";
        await otpRecord.save();

        res.json({ success: true, message: "OTP verified successfully" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// ======================== RESET PASSWORD =========================
app.post("/api/auth/reset-password", async (req, res) => {
    try {
        const { email, newPassword } = req.body;

        // Check if there is a VERIFIED record in the database
        const verifiedRecord = await Otp.findOne({ email, otp: "VERIFIED" });
        if (!verifiedRecord) {
            return res.status(400).json({ success: false, message: "OTP not verified or session expired" });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        // Hash new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        user.password = hashedPassword;
        await user.save();

        // Delete used OTP record
        await Otp.deleteOne({ _id: verifiedRecord._id });

        res.json({ success: true, message: "Password reset successful!" });

    } catch (err) {
        res.status(500).json({ success: false, message: "Server Error" });
    }
});
                              

        



// ====================================================================
// USER PROFILE (View & Update)
// ====================================================================


// 1. Get My Profile Data
app.get("/api/user/my-profile", verifyUser, async (req, res) => {
    try {
        // We add .populate() to automatically fetch the Agent document connected to referredByAgentId
        const user = await User.findById(req.userId)
            .select("-password -otp")
            .populate("referredByAgentId", "name agentCode email mobile"); // Fetch specific agent fields

        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        // --- THE LOGIC YOU REQUESTED ---
        let agentInfo = null;
        
        // Check if the user has an agent attached
        if (user.referredByAgentId) {
            agentInfo = {
                id: user.referredByAgentId._id,
                name: user.referredByAgentId.name,
                agentCode: user.referredByAgentId.agentCode
            };
        }
        // -------------------------------

        // Send the user data AND the formatted agent info back to the frontend
        res.json({ 
            success: true, 
            user: user,
            referredBy: agentInfo // Will be null if no agent, or an object with ID and Name if referred
        });
    } catch (e) {
        res.status(500).json({ success: false, message: "Server Error" });
    }
});


// ====================================================================
// USER PROFILE (View & Update with Photos)
// ====================================================================

// 2. Update Profile Details & Photos simultaneously
app.put("/api/user/update-profile", verifyUser, uploadProfile.array("photos", 5), async (req, res) => {
    try {
        const { 
            firstName, lastName, religion, caste, subCommunity, 
            state, city, education, jobRole, annualIncome, 
            height, diet, maritalStatus, aboutMe,
            gothra, residentsIn, astrologyDetails, familyDetails,
            existingPhotos // <-- Array of photo URLs the user wants to KEEP
        } = req.body;

        // 1. Find User to get their current photos
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        // 2. Handle Photos
        let updatedPhotos = [];

        // Parse existing photos sent from frontend (handles single string or array)
        if (existingPhotos) {
            updatedPhotos = Array.isArray(existingPhotos) ? existingPhotos : [existingPhotos];
        }

        // Identify which old photos are NO LONGER in the updatedPhotos list
        const photosToDelete = user.photos.filter(photo => !updatedPhotos.includes(photo));

        // Delete discarded photos from Cloudinary to save storage
        if (photosToDelete.length > 0) {
            const deletePromises = photosToDelete.map(imageUrl => {
                const parts = imageUrl.split('/');
                const fileWithExt = parts.pop();
                const folder = parts.pop();
                const publicId = `${folder}/${fileWithExt.split('.')[0]}`;
                return cloudinary.uploader.destroy(publicId);
            });
            await Promise.all(deletePromises);
        }

        // Add newly uploaded photos from this request
        if (req.files && req.files.length > 0) {
            const newPhotoUrls = req.files.map(f => f.path);
            updatedPhotos = [...updatedPhotos, ...newPhotoUrls];
        }

        // Ensure we don't exceed the 5 photo limit
        if (updatedPhotos.length > 5) {
            updatedPhotos = updatedPhotos.slice(0, 5);
        }

        // 3. Prepare Update Data
        const updateData = {
            firstName, lastName, religion, caste, subCommunity,
            state, city, highestQualification: education, jobRole, annualIncome,
            height, diet, maritalStatus, aboutMe,
            gothra, residentsIn, astrologyDetails, familyDetails,
            photos: updatedPhotos, // <-- Save the merged photo array
            hasAstrologyAndFamilyDetails: true 
        };

        // 4. Update Database
        const updatedUser = await User.findByIdAndUpdate(
            req.userId, 
            { $set: updateData },
            { new: true } 
        ).select("-password");

        res.json({ success: true, message: "Profile and Photos Updated", user: updatedUser });
        
    } catch (e) {
        console.error("Profile Update Error:", e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});



app.post("/api/user/upload-photos", verifyUser, uploadProfile.array("photos", 5), async (req, res) => {
    try {
        if (!req.files || req.files.length === 0) {
            return res.status(400).json({ success: false, message: "No files uploaded" });
        }

        const photoUrls = req.files.map(f => f.path);

        // Update User Photos
        const user = await User.findByIdAndUpdate(
            req.userId, 
            { $push: { photos: { $each: photoUrls } } }, // Add new photos to existing array
            { new: true }
        );

        res.json({ 
            success: true, 
            message: "Photos uploaded successfully", 
            photos: user.photos 
        });

    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});



// ===================== CHECK IF USER UPLOADED PHOTOS =====================

app.get("/api/user/photos-status", verifyUser, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select("photos");

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        const hasPhotos = user.photos && user.photos.length > 0;

        res.json({
            success: true,
            hasPhotos: hasPhotos  // true if photos exist, false otherwise
        });

    } catch (err) {
        console.error("Photo Status Error:", err);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

app.post("/api/auth/login-init", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email }); 
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        if (!user.isActive) {
            return res.status(403).json({ success: false, message: "ACCESS DENIED: Your account has been restricted by Admin." });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ success: false, message: "Invalid credentials" });

        // Generate OTP
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();


        // Save new OTP to MongoDB
        await Otp.create({ email, otp: otpCode });

        const emailContent = generateEmailTemplate(
            "Login Authentication",
            `<p>You have requested to log in to your account.</p>
             <p>Your One-Time Password (OTP) is:</p>
             <h2 style="color: #2c3e50; letter-spacing: 5px;">${otpCode}</h2>
             <p>This code is valid for 5 minutes. Do not share this code with anyone.</p>`
        );


        await sendMail({ 
    to: email, 
    subject: "Your Login OTP", 
    html: emailContent,
    fromEmail: `"KalyanaShobha Security" <noreply@kalyanashobha.in>`
});
        res.json({ success: true, message: "OTP sent to email." });

    } catch (e) { 
        res.status(500).json({ success: false, message: e.message }); 
    }
});

app.post("/api/auth/login-verify", async (req, res) => {
    try {
        const { email, otp } = req.body;
        
        // Find the OTP in the database
        const cleanOtp = String(otp).trim();
const otpRecord = await Otp.findOne({ email, otp: cleanOtp });


        if (otpRecord) {
            const user = await User.findOne({ email });
            
            // Delete the OTP immediately after successful use
            await Otp.deleteOne({ _id: otpRecord._id }); 
            
            const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || "fallback_secret_key", { expiresIn: "7d" });
            res.json({ success: true, token, user });
        } else {
            res.status(400).json({ success: false, message: "Invalid or Expired OTP" });
        }
    } catch (e) { 
        res.status(500).json({ success: false, message: "Server Error" }); 
    }
});



// ====================================================================
// C. SEARCH (Public)
// ====================================================================
app.post("/api/users/search", async (req, res) => {
    try {
        const { 
            gender, minAge, maxAge, minHeight, maxHeight, 
            religion, caste, education, jobRole, 
            state, city, diet 
        } = req.body;

        let query = { isApproved: true, isActive: true };

        if (gender) query.gender = gender;
        if (religion) query.religion = religion;
        if (caste) query.caste = caste;
        if (education) query.highestQualification = education;
        if (state) query.state = state;
        if (city) query.city = city;
        if (diet) query.diet = diet;

        if (minAge || maxAge) {
            query.dob = {};
            const today = new Date();
            if (minAge) query.dob.$lte = new Date(today.getFullYear() - minAge, today.getMonth(), today.getDate());
            if (maxAge) query.dob.$gte = new Date(today.getFullYear() - maxAge, today.getMonth(), today.getDate());
        }
        if (minHeight || maxHeight) {
            query.height = {};
            if (minHeight) query.height.$gte = parseFloat(minHeight);
            if (maxHeight) query.height.$lte = parseFloat(maxHeight);
        }

        const users = await User.find(query).select('-password -fcmToken');
        res.json({ success: true, count: users.length, data: users });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});


// ====================================================================
// F. USER DASHBOARD (SMART MATCHES: Age + Community + Marital Status)
// ====================================================================



// ====================================================================
// F. USER DASHBOARD (SMART MATCHES: Age + Community + Marital Status)
// ====================================================================

// ====================================================================
// F. USER DASHBOARD (SMART MATCHES WITH STATUS)
// ====================================================================

app.get("/api/user/dashboard-matches", verifyUser, async (req, res) => {
    try {
        const currentUser = await User.findById(req.userId);
        if (!currentUser) return res.status(404).json({ success: false, message: "User not found" });

        // 1. Fetch ALL interactions (Sent or Received)
        const interactions = await Interest.find({
            $or: [
                { senderId: req.userId }, 
                { receiverId: req.userId }
            ]
        });

        // 2. Create a Map for quick lookup:  UserID -> Status
        // Example: { "65df...": "PendingPaymentVerification", "65da...": "Accepted" }
        const statusMap = {};
        interactions.forEach(inter => {
            const otherId = inter.senderId.toString() === req.userId.toString() 
                ? inter.receiverId.toString() 
                : inter.senderId.toString();
            
            statusMap[otherId] = inter.status;
        });

        // 3. Define Limits
        const isPremium = currentUser.isApproved && currentUser.isPaidMember;
        const profileLimit = isPremium ? 50 : 10; // Give free users some matches to see status

        // 4. Build Query
        const targetGender = currentUser.gender === 'Male' ? 'Female' : 'Male';
        let query = {
            gender: targetGender,
            isApproved: true,
            isActive: true,
            _id: { $ne: req.userId } // Only exclude myself
        };

        // --- FILTER 1: COMMUNITY ---
        if (currentUser.caste) query.caste = currentUser.caste;

        // --- FILTER 2: MARITAL STATUS ---
        if (currentUser.maritalStatus === 'Never Married') {
            query.maritalStatus = 'Never Married';
        } else {
            query.maritalStatus = { $in: ['Divorced', 'Widowed', 'Awaiting Divorce'] };
        }

        // --- FILTER 3: AGE ---
        if (currentUser.dob) {
            const userDob = new Date(currentUser.dob);
            const userYear = userDob.getFullYear();
            const today = new Date();
            const currentYear = today.getFullYear();
            let minAge, maxAge;

            if (currentUser.gender === 'Male') {
                const myAge = currentYear - userYear;
                minAge = myAge - 5; maxAge = myAge;     
            } else {
                const myAge = currentYear - userYear;
                minAge = myAge; maxAge = myAge + 5; 
            }
            const minDobDate = new Date(currentYear - maxAge, 0, 1); 
            const maxDobDate = new Date(currentYear - minAge, 11, 31); 
            query.dob = { $gte: minDobDate, $lte: maxDobDate };
        }

        // 5. Fetch Profiles
        const matches = await User.find(query)
            .select('firstName lastName dob caste highestQualification jobRole maritalStatus photos city state')
            .limit(profileLimit);

        // 6. Format Output & ATTACH STATUS
        const formattedMatches = matches.map(profile => {
            const dob = new Date(profile.dob);
            const ageDiffMs = Date.now() - dob.getTime();
            const ageDate = new Date(ageDiffMs);
            const age = Math.abs(ageDate.getUTCFullYear() - 1970);

            // LOOKUP STATUS
            const status = statusMap[profile._id.toString()] || null;

            return {
                id: profile._id,
                name: `${profile.firstName} ${profile.lastName}`,
                age: age,
                subCommunity: profile.caste,
                education: profile.highestQualification, 
                job: profile.jobRole,
                maritalStatus: profile.maritalStatus,
                photo: profile.photos.length > 0 ? profile.photos[0] : null,
                location: `${profile.city}, ${profile.state}`,
                
                // *** THIS IS THE NEW FIELD ***
                interestStatus: status 
            };
        });

        res.json({ 
            success: true, 
            count: formattedMatches.length, 
            isPremium, 
            data: formattedMatches 
        });

    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false, message: "Error fetching matches" });
    }
});
 

// ====================================================================
// D. ADMIN DASHBOARD & MANAGEMENT (SECURE)
// ====================================================================

app.get("/api/admin/stats", verifyAdmin, async (req, res) => {
    try {
        const [
            // 1. User Stats
            totalUsers,
            males,
            females,
            blockedUsers,
            pendingUserApprovals,
            
            // 2. Referral Tracking (New)
            totalReferredUsers, // Users who signed up via an Agent

            // 3. Action Queue (Things you need to verify)
            pendingRegPayments, // Membership payments waiting for UTR check
            pendingIntPayments, // Contact payments waiting for UTR check
            pendingIntContent,  // Messages waiting for content moderation
            
            // 4. Platform Health
            totalAgents,
            totalVendors,
            totalInterests,
            acceptedInterests
        ] = await Promise.all([
            // User Counts
            User.countDocuments({}),
            User.countDocuments({ gender: 'Male' }),
            User.countDocuments({ gender: 'Female' }),
            User.countDocuments({ isActive: false }),
            User.countDocuments({ isApproved: false }),

            // REFERRAL TRACKING: Count users where 'referredByAgentId' is NOT null
            User.countDocuments({ referredByAgentId: { $ne: null } }),

            // Action Queue
            PaymentRegistration.countDocuments({ status: 'PendingVerification' }),
            PaymentInterest.countDocuments({ status: 'PendingPaymentVerification' }),
            Interest.countDocuments({ status: 'PendingAdmin' }),

            // General Counts
            Agent.countDocuments({}),
            Vendor.countDocuments({}),
            Interest.countDocuments({}),
            // FIXED: Changed 'Accepted' to 'Finalized' to match your Schema
            Interest.countDocuments({ status: 'Finalized' }) 
        ]);

        res.json({
            success: true,
            stats: {
                users: {
                    total: totalUsers,
                    males,
                    females,
                    blocked: blockedUsers,
                },
                referrals: {
                    totalAgents: totalAgents,
                    totalReferredUsers: totalReferredUsers, // How many users agents brought in
                },
                actionQueue: {
                    pendingUserApprovals,           // Profiles waiting to be approved
                    pendingRegistrationPayments: pendingRegPayments, // Memberships to Verify
                    pendingInterestPayments: pendingIntPayments,     // Contact Requests to Verify
                    pendingInterestContent: pendingIntContent        // Messages to Approve
                },
                platformHealth: {
                    totalVendors,
                    totalInterestsSent: totalInterests,
                    successfulMatches: acceptedInterests
                }
            }
        });

    } catch (e) {
        console.error("Stats Error:", e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});




app.get("/api/admin/users", verifyAdmin, async (req, res) => {
    const users = await User.find().sort({ createdAt: -1 });
    res.json({ success: true, users });
});

app.post("/api/admin/users/status", verifyAdmin, async (req, res) => {
    try {
        const { userId, action, reason } = req.body; 
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ message: "User not found" });

        if (action === 'approve') {
            user.isApproved = true; user.rejectionReason = null;
            const emailContent = generateEmailTemplate(
                "Profile Approved",
                `<p>We are pleased to inform you that your profile has been successfully verified and approved by our administration team.</p>
                 <p>Your profile is now visible to other members. Good luck with your search.</p>`
            );
            await sendMail({ 
    to: user.email, 
    subject: "Profile Status: Approved", 
    html: emailContent,
    fromEmail: `"KalyanaShobha Admin" <admin@kalyanashobha.in>` 
});
        } else if (action === 'reject') {
            user.isApproved = false; user.rejectionReason = reason;
            const emailContent = generateEmailTemplate(
                "Profile Update Required",
                `<p>We reviewed your profile but could not approve it at this time.</p>
                 <p><strong>Reason:</strong> ${reason}</p>
                 <p>Please log in and update your profile information or photos accordingly to be reconsidered.</p>`
            );
             // For Rejection
     await sendMail({ 
         to: user.email, 
         subject: "Action Required: Profile Update", 
         html: emailContent,
         fromEmail: `"KalyanaShobha Admin" <admin@kalyanashobha.in>`
         });
            
        } else if (action === 'block') { user.isActive = false; }
          else if (action === 'unblock') { user.isActive = true; }

        await user.save();
        res.json({ success: true, message: `User ${action}ed` });
    } catch (e) { res.status(500).json({ success: false }); }
});




// ====================================================================
// NEW: SPECIFIC ADVANCED SEARCH API
// ====================================================================

// ====================================================================
// NEW: SPECIFIC ADVANCED SEARCH API (Updated for Astrology)
// ====================================================================

app.post("/api/admin/users/search-advanced", verifyAdmin, async (req, res) => {
    try {
        const {
            // Basic
            memberId, gender, maritalStatus,
            // Age Range
            minAge, maxAge,
            // Location
            country, state, city,
            // Community
            religion, community, caste, subCommunity, motherTongue, star,
            // Professional
            education, occupation
        } = req.body;

        let query = {};

        // 1. Exact Match Fields
        if (memberId) query.uniqueId = { $regex: memberId, $options: 'i' };
        if (gender) query.gender = gender;
        if (maritalStatus) query.maritalStatus = maritalStatus;
        if (religion) query.religion = religion;
        if (community) query.community = community;
        
        // Match both 'caste' and 'subCommunity' strings since they are often used interchangeably
        if (caste) query.caste = { $regex: caste, $options: 'i' };
        if (subCommunity) query.subCommunity = { $regex: subCommunity, $options: 'i' };
        
        if (country) query.country = { $regex: country, $options: 'i' };
        if (state) query.state = { $regex: state, $options: 'i' };
        if (city) query.city = { $regex: city, $options: 'i' };

        // 2. Astrology Details (NEW)
        if (motherTongue) query['astrologyDetails.motherTongue'] = { $regex: motherTongue, $options: 'i' };
        if (star) query['astrologyDetails.star'] = { $regex: star, $options: 'i' };

        // 3. Professional (Partial Matches)
        if (education) query.highestQualification = { $regex: education, $options: 'i' };
        if (occupation) query.jobRole = { $regex: occupation, $options: 'i' };

        // 4. Age Calculation (Converting Age to Date of Birth range)
        if (minAge || maxAge) {
            const today = new Date();
            query.dob = {};

            if (maxAge) {
                // If max age is 30, birth date must be >= 30 years ago
                const maxDate = new Date(new Date().setFullYear(today.getFullYear() - maxAge));
                query.dob.$gte = maxDate; 
            }

            if (minAge) {
                // If min age is 20, birth date must be <= 20 years ago
                const minDate = new Date(new Date().setFullYear(today.getFullYear() - minAge));
                query.dob.$lte = minDate;
            }
        }

        const users = await User.find(query).select('-password');

        res.json({ 
            success: true, 
            count: users.length, 
            users 
        });

    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});
            





// ====================================================================
// G. AGENT MANAGEMENT (Refined)
// ====================================================================

// 1. Create Agent (With Password Hash, Code Gen & EMAIL NOTIFICATION)
app.post("/api/admin/agents", verifyAdmin, async (req, res) => {
    try {
        const { name, mobile, email, password } = req.body;

        // Check duplicates
        const existing = await Agent.findOne({ $or: [{ email }, { mobile }] });
        if (existing) return res.status(400).json({ success: false, message: "Agent exists with this email/mobile" });

        // Hash Password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Generate Unique Agent Code (e.g., AGT-8392)
        const agentCode = `AGT-${Math.floor(1000 + Math.random() * 9000)}`;

        const agent = new Agent({
            name, mobile, email, 
            password: hashedPassword, 
            agentCode,
            isActive: true
        });

        await agent.save();

        // --- NEW: SEND WELCOME EMAIL TO AGENT ---
        const agentEmailContent = generateEmailTemplate(
            "Welcome to KalyanaShobha Agent Portal",
            `<p>Dear ${agent.name},</p>
             <p>Your agent account has been successfully created by the administrator.</p>
             <p>Here are your official login credentials:</p>
             <table style="width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; background: #fafafa; border: 1px solid #eeeeee;">
                <tr>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; width: 40%; color: #555;"><strong>Login URL:</strong></td>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee;"><a href="https://kalyanashobha.in/agent/login" style="color: #D32F2F; text-decoration: none; font-weight: bold;">kalyanashobha.in/agent</a></td>
                </tr>
                <tr>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #555;"><strong>Email ID:</strong></td>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #222; font-weight: bold;">${email}</td>
                </tr>
                <tr>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #555;"><strong>Password:</strong></td>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #222; font-weight: bold;">${password}</td>
                </tr>
                <tr>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #555;"><strong>Agent Code:</strong></td>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #222; font-weight: bold;">${agentCode}</td>
                </tr>
             </table>
             <p style="margin-top: 20px;">Please keep these credentials safe and do not share them with anyone.</p>
             <div style="margin-top: 30px; text-align: center;">
                <a href="https://www.kalyanashobha.in/agent/login" style="background-color: #D32F2F; color: white; padding: 12px 25px; text-decoration: none; border-radius: 4px; font-size: 14px; font-weight: bold; display: inline-block;">Login to Dashboard</a>
             </div>`
        );

        // Send the email but don't stop the request if it fails
        try {
            await sendMail({ 
                to: email, 
                subject: "Your Agent Portal Login Credentials", 
                html: agentEmailContent 
            });
            console.log("Agent welcome email sent.");
        } catch (mailErr) {
            console.error("Failed to send agent email:", mailErr);
        }

        res.json({ success: true, message: "Agent created and email sent", agent });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});


// 2. Get All Agents (With Referral Counts)
app.get("/api/admin/agents", verifyAdmin, async (req, res) => {
    try {
        const agents = await Agent.find().sort({ createdAt: -1 });
        
        // Calculate referral counts for each agent
        const agentsWithStats = await Promise.all(agents.map(async (agent) => {
            const count = await User.countDocuments({ referredByAgentId: agent._id });
            return { ...agent.toObject(), referralCount: count };
        }));

        res.json({ success: true, agents: agentsWithStats });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// 3. Get Single Agent + Their Referred Users
app.get("/api/admin/agents/:id/details", verifyAdmin, async (req, res) => {
    try {
        const agent = await Agent.findById(req.params.id);
        if(!agent) return res.status(404).json({success: false, message: "Agent not found"});

        // Fetch users referred by this agent
        const referredUsers = await User.find({ referredByAgentId: agent._id })
            .select('firstName lastName uniqueId mobileNumber email isPaidMember createdAt')
            .sort({ createdAt: -1 });

        res.json({ success: true, agent, users: referredUsers });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// 4. Delete Agent
app.delete("/api/admin/agents/:id", verifyAdmin, async (req, res) => {
    try {
        await Agent.findByIdAndDelete(req.params.id);
        // Optional: You might want to nullify the referredByAgentId in users, 
        // but keeping it for history is usually better.
        res.json({ success: true, message: "Agent deleted" });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// ====================================================================
// ADMIN: VENDOR MANAGEMENT (POST, GET, DELETE)
// ====================================================================

// 1. POST: Create a new Vendor by Admin (Auto-Approved)
app.post("/api/admin/vendors", verifyAdmin, uploadVendor.array("images", 5), async (req, res) => {
  try {
    const images = req.files && req.files.length > 0 
      ? req.files.map(file => file.path) 
      : [];

    // Added email to the destructured body
    const { businessName, email, category, description, contactNumber, priceRange } = req.body;

    if (!businessName || !email || !category || !contactNumber) {
      return res.status(400).json({ success: false, message: "Business Name, Email, Category, and Contact Number are required." });
    }

    const vendorId = await generateVendorId();

    const vendor = new Vendor({
      vendorId, 
      businessName,
      email, // Save email
      category,
      description,
      contactNumber,
      priceRange,
      images,
      isApproved: true // Auto-approved since admin is adding it
    });

    await vendor.save();
    res.json({ success: true, message: "Vendor created successfully", vendor });
  } catch (error) { 
    console.error("Vendor POST Error:", error);
    res.status(500).json({ success: false, message: error.message || "Failed to create vendor" }); 
  }
});



// 2. GET: Fetch all Vendors for Admin Dashboard
app.get("/api/admin/vendors", verifyAdmin, async (req, res) => {
  try {
    // Sort by newest first
    const vendors = await Vendor.find().sort({ createdAt: -1 });
    res.json({ success: true, count: vendors.length, vendors });
  } catch (error) {
    console.error("Vendor GET Error:", error);
    res.status(500).json({ success: false, message: "Failed to fetch vendors" });
  }
});

// 3. DELETE: Remove Vendor AND clean up Cloudinary images
app.delete("/api/admin/vendors/:id", verifyAdmin, async (req, res) => {
  try {
    const vendor = await Vendor.findById(req.params.id);
    if (!vendor) {
      return res.status(404).json({ success: false, message: "Vendor not found" });
    }

    // --- CLOUDINARY CLEANUP ---
    // We must delete the images from Cloudinary so you don't run out of storage space
    if (vendor.images && vendor.images.length > 0) {
      const deletePromises = vendor.images.map(imageUrl => {
        // Extract the Cloudinary public_id from the URL
        // Example URL: https://res.cloudinary.com/demo/image/upload/v1234/matrimony_vendors/xyz.jpg
        const parts = imageUrl.split('/');
        const fileWithExt = parts.pop(); // "xyz.jpg"
        const folder = parts.pop(); // "matrimony_vendors"
        const publicId = `${folder}/${fileWithExt.split('.')[0]}`; // "matrimony_vendors/xyz"
        
        return cloudinary.uploader.destroy(publicId);
      });
      
      // Wait for all images to be deleted from Cloudinary
      await Promise.all(deletePromises);
    }

    // Now delete from MongoDB
    await Vendor.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: "Vendor and associated images deleted successfully" });
  } catch (error) {
    console.error("Vendor DELETE Error:", error);
    res.status(500).json({ success: false, message: "Failed to delete vendor" });
  }
});
            

// 1. Submit Payment (User) - UPDATED WITH DUPLICATE & SUCCESS CHECK
app.post("/api/payment/registration/submit", verifyUser, uploadPayment.single("screenshot"), async (req, res) => {
    try {
        // --- NEW LOGIC START: Check for existing pending OR successful request ---
        const existingPayment = await PaymentRegistration.findOne({ 
            userId: req.userId, 
            status: { $in: ['PendingVerification', 'Success'] } 
        });

        if (existingPayment) {
            // CLOUDINARY CLEANUP: Delete the uploaded file to save storage space
            if (req.file && req.file.filename) {
                await cloudinary.uploader.destroy(req.file.filename);
            }

            // Set dynamic message based on exact status
            let msg = "You have already submitted a payment request. Please wait for admin verification.";
            if (existingPayment.status === 'Success') {
                msg = "Your payment has already been approved. You are already a premium member.";
            }

            return res.json({ 
                success: false, 
                message: msg, 
                status: existingPayment.status,
                alreadySubmitted: true 
            });
        }
        // --- NEW LOGIC END ---

        const { amount, utrNumber } = req.body;
        const user = await User.findById(req.userId);

        if (!req.file) {
            return res.status(400).json({ success: false, message: "Screenshot is required" });
        }

        const payment = new PaymentRegistration({
            userId: req.userId, 
            amount, 
            utrNumber, 
            screenshotUrl: req.file.path,
            status: 'PendingVerification'
        });
        await payment.save();

        // --- USER EMAIL CONTENT ---
        const userEmailContent = generateEmailTemplate(
            "Payment Received",
            `<p>We have received your payment submission of <strong>Rs. ${amount}</strong>.</p>
             <p>Our team will verify the transaction details (UTR: ${utrNumber}) within 24 hours.</p>
             <p>You will be notified once your membership is activated.</p>`
        );

        // --- ADMIN EMAIL CONTENT (Professional Template) ---
        const adminEmailContent = generateEmailTemplate(
            "New Payment Verification Required",
            `<p>A new membership payment has been submitted and requires your verification.</p>
             <table style="width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; background: #fafafa; border: 1px solid #eeeeee;">
                <tr>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; width: 40%; color: #555;"><strong>User Name:</strong></td>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #222; font-weight: bold;">${user.firstName} ${user.lastName}</td>
                </tr>
                <tr>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #555;"><strong>Profile ID:</strong></td>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #D32F2F; font-weight: bold;">${user.uniqueId}</td>
                </tr>
                <tr>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #555;"><strong>Amount Paid:</strong></td>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #2e7d32; font-weight: bold; font-size: 16px;">₹${amount}</td>
                </tr>
                <tr>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #555;"><strong>UTR Number:</strong></td>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #222;">${utrNumber}</td>
                </tr>
             </table>
             <div style="margin-top: 30px; text-align: center;">
                <a href="https://kalyanashobha.in/admin" style="background-color: #D32F2F; color: white; padding: 12px 25px; text-decoration: none; border-radius: 4px; font-size: 14px; font-weight: bold; display: inline-block;">Verify in Admin Dashboard</a>
             </div>`
        );

        // 1. Create the promises (start sending)
        const sendUserMail = sendMail({ 
            to: user.email, 
            subject: "Payment Submission Received", 
            html: userEmailContent 
        });

        // Use environment variable or fallback to your info email
        
        const sendAdminMail = sendMail({ 
            to: EMAIL_USER,
            subject: `Action Required: Payment from ${user.uniqueId}`, 
            html: adminEmailContent 
        });

        // 2. Wait for both to complete
        try {
            await Promise.all([sendUserMail, sendAdminMail]);
            console.log("Payment emails sent successfully.");
        } catch (emailError) {
            console.error("Warning: Payment emails failed, but DB record saved.", emailError);
        }

        res.json({ success: true, message: "Submitted successfully", status: "PendingVerification" });

    } catch (e) { 
        console.error("Payment Submission Error:", e);
        res.status(500).json({ success: false, message: "Server Error" }); 
    }
});
                             




// ====================================================================
// NEW API: GET LATEST REGISTRATION PAYMENT STATUS
// ====================================================================

app.get("/api/payment/registration/status", verifyUser, async (req, res) => {
    try {
        // 1. Find the LATEST payment submission for this user
        // We sort by date: -1 to get the newest one first
        const latestPayment = await PaymentRegistration.findOne({ userId: req.userId })
            .sort({ date: -1 });

        // 2. If no payment record exists at all
        if (!latestPayment) {
            return res.json({
                success: true,
                paymentFound: false,
                message: "No payment history found."
            });
        }

        // 3. Return the details
        res.json({
            success: true,
            paymentFound: true,
            data: {
                amount: latestPayment.amount,
                utrNumber: latestPayment.utrNumber,
                screenshotUrl: latestPayment.screenshotUrl, // The uploaded proof
                status: latestPayment.status,               // 'PendingVerification', 'Success', 'Rejected'
                adminNote: latestPayment.adminNote,         // If admin rejected, reason will be here
                date: latestPayment.date
            }
        });

    } catch (e) {
        console.error("Payment Status Error:", e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});


// ====================================================================
// NEW: GET Pending Interest Requests (For Admin List)
// ====================================================================

app.get("/api/admin/interest/requests", verifyAdmin, async (req, res) => {
    try {
        const { status } = req.query; // e.g., 'PendingPaymentVerification'

        let query = {};
        if (status) {
            query.status = status;
        }

        // 1. Find Payments based on status
        const payments = await PaymentInterest.find(query)
            .populate('senderId', 'firstName lastName uniqueId')
            .populate('receiverId', 'firstName lastName uniqueId')
            .sort({ date: -1 });

        // 2. We also need the 'interestId' for the second API call.
        // We map over payments and find the related Interest document.
        const combinedData = await Promise.all(payments.map(async (pay) => {
            const interest = await Interest.findOne({ paymentId: pay._id });
            return {
                _id: pay._id,                // Payment ID
                interestId: interest?._id,   // Interest ID (Needed for Step 2)
                amount: pay.amount,
                utrNumber: pay.utrNumber,
                screenshotUrl: pay.screenshotUrl,
                status: pay.status,
                date: pay.date,
                sender: pay.senderId,
                receiver: pay.receiverId
            };
        }));

        res.json({ success: true, data: combinedData });

    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});










// ====================================================================
// NEW: GET Payment Registrations (For Admin List)
// ====================================================================

app.get("/api/admin/payment/registrations", verifyAdmin, async (req, res) => {
    try {
        const { status } = req.query;
        
        // Build query based on status (PendingVerification, Success, Rejected)
        // If no status provided, default to all or handle on frontend
        let query = {};
        if (status) {
            query.status = status;
        }

        const payments = await PaymentRegistration.find(query)
            .populate('userId', 'firstName lastName uniqueId mobileNumber email') // Get User Details
            .sort({ date: -1 }); // Newest first

        res.json({ success: true, count: payments.length, payments });

    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});


// 2. Admin Verify Registration
app.post("/api/admin/payment/registration/verify", verifyAdmin, async (req, res) => {
    try {
        const { paymentId, action } = req.body;

        // Find the payment record
        const payment = await PaymentRegistration.findById(paymentId);
        if (!payment) return res.status(404).json({ success: false, message: "Payment not found" });

        // Find the user associated with this payment
        const user = await User.findById(payment.userId);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        if (action === "approve") {
            // --- UPDATED LOGIC START ---
            payment.status = "Success"; 

            user.isPaidMember = true;   // Mark as Paid
            user.isApproved = true;     // MAKE VISIBLE TO OTHERS (Profile Approved)
            user.isActive = true;       // Ensure account is active/unblocked

            // Save both
            await payment.save(); 
            await user.save();
            // --- UPDATED LOGIC END ---

            const emailContent = generateEmailTemplate(
                "Membership Activated",
                `<p>We verified your payment successfully.</p>
                 <p>Your Paid Membership is now <strong>Active</strong>. Your profile is now visible to matches and you can access premium features.</p>`
            );

            // ---------------------------------------------------------
            // CORRECTION: Add await so the loop waits for email to send
            // ---------------------------------------------------------
            try {
               // For Success
await sendMail({ 
    to: user.email, 
    subject: "Membership Activated", 
    html: emailContent,
    fromEmail: `"KalyanaShobha Admin" <admin@kalyanashobha.in>`
});
                
                console.log("Approval email sent.");
            } catch (emailErr) {
                console.error("Failed to send approval email:", emailErr);
            }

        } else {
            // Rejection Logic
            payment.status = "Rejected"; 
            await payment.save();

            const emailContent = generateEmailTemplate(
                "Payment Verification Failed",
                `<p>We could not verify your recent payment transaction.</p>
                 <p>Please check if the UTR number or screenshot provided was correct and try submitting again.</p>`
            );

            // ---------------------------------------------------------
            // CORRECTION: Add await here too
            // ---------------------------------------------------------
            try {
                // For Rejection
await sendMail({ 
    to: user.email, 
    subject: "Action Required: Payment Issue", 
    html: emailContent,
    fromEmail: `"KalyanaShobha Admin" <admin@kalyanashobha.in>`
});
                console.log("Rejection email sent.");
            } catch (emailErr) {
                console.error("Failed to send rejection email:", emailErr);
            }
        }

        res.json({ success: true, message: "Action processed successfully" });

    } catch (e) { 
        console.error(e);
        res.status(500).json({ success: false, message: "Server Error" }); 
    }
});
                                



// 3. Submit Interest (User) - UPDATED WITH DUPLICATE CHECK

app.post("/api/interest/submit-proof", verifyUser, uploadPayment.single("screenshot"), async (req, res) => {
    try {
        const { receiverId, amount, utrNumber } = req.body;

        // --- NEW LOGIC START: DUPLICATE CHECK ---
        const existingInterest = await Interest.findOne({
            senderId: req.userId,
            receiverId: receiverId,
            status: { $ne: 'Rejected' } 
        });

        if (existingInterest) {
            // Delete the uploaded file to save cloud storage space
            if (req.file) {
                await cloudinary.uploader.destroy(req.file.filename);
            }

            let msg = "Request already exists.";
            if (existingInterest.status === 'Accepted') msg = "You are already connected with this user.";
            if (existingInterest.status === 'Declined') msg = "This user has previously declined your request.";
            if (existingInterest.status.includes('Pending')) msg = "A request is already pending verification or approval.";

            return res.json({ 
                success: false, 
                message: msg, 
                currentStatus: existingInterest.status 
            });
        }
        // --- NEW LOGIC END ---

        // 1. Fetch user details for the email
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        if (!req.file) return res.status(400).json({ success: false, message: "Screenshot required" });

        // 2. Save Payment Record
        const payment = new PaymentInterest({
            senderId: req.userId, 
            receiverId, 
            amount, 
            utrNumber, 
            screenshotUrl: req.file.path
        });
        await payment.save();

        // 3. Create Interest Record
        const interest = new Interest({
            senderId: req.userId, 
            receiverId, 
            paymentId: payment._id, 
            status: "PendingPaymentVerification"
        });
        await interest.save();

        // 4. PREPARE EMAIL CONTENT
        const userEmailContent = generateEmailTemplate(
            "Interest Request Received",
            `<p>Dear ${user.firstName},</p>
             <p>We have received your interest request and the payment proof of <strong>Rs. ${amount}</strong>.</p>
             <p>Our administration team is currently verifying the transaction details (UTR: ${utrNumber}). Once verified, your interest will be forwarded to the recipient.</p>
             <p>Status: Payment Verification Pending</p>`
        );

        const adminEmailContent = generateEmailTemplate(
            "Action Required: New Interest Payment",
            `<p>A new interest payment has been submitted for verification.</p>
             <p><strong>Sender:</strong> ${user.firstName} (${user.uniqueId})<br>
                <strong>UTR Number:</strong> ${utrNumber}<br>
                <strong>Amount:</strong> Rs. ${amount}</p>
             <p>Please log in to the Admin Dashboard to verify the screenshot and approve the request.</p>`
        );

        // ---------------------------------------------------------
        // CORRECTION START: Wait for emails to send parallelly
        // ---------------------------------------------------------

        // 1. Create promises (start sending)
        const sendUserMail = sendMail({ 
            to: user.email, 
            subject: "Notification: Interest Request Submitted", 
            html: userEmailContent 
        });

        const sendAdminMail = sendMail({ 
            to: EMAIL_USER,
            subject: "Admin Alert: New Interest Verification Required", 
            html: adminEmailContent 
        });

        // 2. Wait for both to complete
        try {
            await Promise.all([sendUserMail, sendAdminMail]);
            console.log("Interest submission emails sent successfully.");
        } catch (emailError) {
            console.error("Warning: Emails failed to send.", emailError);
        }

        // ---------------------------------------------------------
        // CORRECTION END
        // ---------------------------------------------------------

        res.json({ success: true, message: "Interest Request and Payment Proof Submitted" });

    } catch (e) {
        console.error("Interest Submission Error:", e.message);
        return res.status(500).json({ success: false, error: e.message });
    }
});

// 4. Admin Verify Interest Payment
app.post("/api/admin/payment/interest/verify", verifyAdmin, async (req, res) => {
    try {
        const { paymentId, action } = req.body;
        
        // Populate senderId to get Name and Email
        const payment = await PaymentInterest.findById(paymentId).populate('senderId'); 
        const interest = await Interest.findOne({ paymentId });

        if (!payment || !interest) {
            return res.status(404).json({ success: false, message: "Payment or Interest record not found" });
        }

        if (action === "approve") {
            payment.status = "Success"; 
            interest.status = "PendingAdmin";

            // 1. CRITICAL FIX: Save DB *before* sending email
            // This ensures the status updates even if email fails
            await payment.save(); 
            await interest.save();

            const emailContent = generateEmailTemplate(
                "Payment Verified",
                `<p>Dear ${payment.senderId.firstName},</p>
                 <p>Your payment for the interest request has been verified.</p>
                 <p>Your request is now under final content review by our team.</p>`
            );

            // 2. Send Email with Error Handling (so it doesn't crash the response)
            try {
                await sendMail({ to: payment.senderId.email, subject: "Payment Successful", html: emailContent });
                console.log("Interest payment approval email sent.");
            } catch (emailErr) {
                console.error("Failed to send approval email:", emailErr);
            }

        } else {
            payment.status = "Rejected"; 
            interest.status = "Rejected";

            // 1. CRITICAL FIX: Save DB *before* sending email
            await payment.save(); 
            await interest.save();

            const emailContent = generateEmailTemplate(
                "Payment Verification Failed",
                `<p>Dear ${payment.senderId.firstName},</p>
                 <p>We were unable to verify your payment for the interest request.</p>
                 <p>Please ensure the transaction details are correct and submit again.</p>`
            );

            // 2. Send Email with Error Handling
            try {
                await sendMail({ to: payment.senderId.email, subject: "Payment Verification Issue", html: emailContent });
                console.log("Interest payment rejection email sent.");
            } catch (emailErr) {
                console.error("Failed to send rejection email:", emailErr);
            }
        }
        
        res.json({ success: true, message: "Action processed successfully" });

    } catch (e) { 
        console.error(e);
        res.status(500).json({ success: false, message: "Server Error" }); 
    }
});

// 5. Admin Approve Interest Content
app.post("/api/admin/interest/approve-content", verifyAdmin, async (req, res) => {
    try {
        const { interestId, action } = req.body;
        
        // Populate both to send emails. 
        // We select specific fields to ensure we have the names and emails.
        const interest = await Interest.findById(interestId)
            .populate('receiverId', 'firstName lastName email')
            .populate('senderId', 'firstName lastName email');

        if (!interest) {
            return res.status(404).json({ success: false, message: "Interest record not found" });
        }

        if (action === "approve") {
            interest.status = "PendingUser";
            await interest.save(); // Save DB status first!

            // --- FIX: Use firstName + lastName instead of username ---
            const senderName = `${interest.senderId.firstName} ${interest.senderId.lastName}`;
            const receiverName = `${interest.receiverId.firstName} ${interest.receiverId.lastName}`;

            // Mail to Sender (Confirmation)
            const senderContent = generateEmailTemplate(
                "Request Forwarded",
                `<p>Your interest request has been approved by our team and forwarded to the profile of <strong>${receiverName}</strong>.</p>
                 <p>You will be notified once they respond.</p>`
            );
            
            // Mail to Receiver (Notification)
            const receiverContent = generateEmailTemplate(
                "New Interest Received",
                `<p>You have received a new interest from <strong>${senderName}</strong>.</p>
                 <p>Please log in to your dashboard to view their profile and accept or decline this request.</p>`
            );

            // --- FIX: Send both emails in parallel and wait ---
            try {
                await Promise.all([
                    sendMail({ to: interest.senderId.email, subject: "Request Forwarded", html: senderContent }),
                    sendMail({ to: interest.receiverId.email, subject: "New Interest Notification", html: receiverContent })
                ]);
                console.log("Interest content approval emails sent.");
            } catch (emailErr) {
                console.error("Failed to send interest approval emails:", emailErr);
            }

        } else {
            // Rejection Logic
            interest.status = "Rejected";
            await interest.save(); // Save DB status first!

            const senderContent = generateEmailTemplate(
                "Request Status",
                `<p>Your interest request could not be forwarded as it did not meet our content guidelines.</p>`
            );

            // --- FIX: Add await ---
            try {
                await sendMail({ to: interest.senderId.email, subject: "Interest Request Update", html: senderContent });
                console.log("Interest content rejection email sent.");
            } catch (emailErr) {
                console.error("Failed to send interest rejection email:", emailErr);
            }
        }
        
        res.json({ success: true, message: "Action processed successfully" });

    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});


app.post("/api/user/interest/respond", verifyUser, async (req, res) => {
    try {
        const { interestId, action } = req.body;

        const interest = await Interest.findById(interestId)
            .populate('senderId', 'firstName lastName email')
            .populate('receiverId', 'firstName lastName email');

        if (!interest) return res.status(404).json({ success: false, message: "Interest not found" });

        if (interest.receiverId._id.toString() !== req.userId) {
            return res.status(403).json({ success: false, message: "Not your request" });
        }

        const receiverName = `${interest.receiverId.firstName} ${interest.receiverId.lastName}`;

        if (action === "accept") {
            // Send back to Admin, NOT to User A
            interest.status = "PendingAdminPhase2";
            await interest.save();

            const adminContent = generateEmailTemplate(
                "Interest Accepted (Phase 2 Action Required)",
                `<p><strong>${receiverName}</strong> has ACCEPTED the interest from <strong>${interest.senderId.firstName}</strong>.</p>
                 <p>Both users have agreed to connect. Please log in to your dashboard to access their contact details and finalize the match offline.</p>`
            );
            sendMail({ to: process.env.EMAIL_USER, subject: "Phase 2 Alert: Interest Accepted", html: adminContent });

            res.json({ success: true, message: "Acceptance sent to Admin. They will contact you shortly." });

        } else {
            interest.status = "Declined";
            await interest.save();
            res.json({ success: true, message: "You have declined this request." });
        }

    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// 7. Get Contact Details
app.post("/api/user/get-contact", verifyUser, async (req, res) => {
    try {
        const { targetUserId } = req.body;
        const connection = await Interest.findOne({
            $or: [
                { senderId: req.userId, receiverId: targetUserId, status: "Accepted" },
                { senderId: targetUserId, receiverId: req.userId, status: "Accepted" }
            ]
        });

        if (connection) {
            const target = await User.findById(targetUserId).select("mobileNumber email");
            res.json({ success: true, contact: target });
        } else {
            res.status(403).json({ success: false, message: "Locked" });
        }
    } catch (e) { res.status(500).json({ success: false }); }
});




// ====================================================================
// PAYMENT HISTORY
// ====================================================================

app.get("/api/user/payment-history", verifyUser, async (req, res) => {
    try {
        // Fetch Membership Payments
        const membershipPayments = await PaymentRegistration.find({ userId: req.userId })
            .sort({ date: -1 });

        // Fetch Interest Payments (Where I am the sender)
        const interestPayments = await PaymentInterest.find({ senderId: req.userId })
            .populate('receiverId', 'firstName lastName') // Show who I paid for
            .sort({ date: -1 });

        res.json({ 
            success: true, 
            membershipHistory: membershipPayments,
            interestHistory: interestPayments 
        });
    } catch (e) {
        res.status(500).json({ success: false, message: "Error fetching payments" });
    }
});



// ====================================================================
// INTERESTS DASHBOARD (Sent & Received)
// ====================================================================

// 1. Get "Received" Interests (Requests others sent to ME)
app.get("/api/user/interests/received", verifyUser, async (req, res) => {
    try {
        const requests = await Interest.find({ 
            receiverId: req.userId,
            // Show all requests that haven't been completed yet
            status: { $in: ['PendingUser', 'PendingAdminPhase2', 'Finalized', 'Declined'] } 
        })
        // POPULATE ALL DASHBOARD FIELDS
        .populate('senderId', 'firstName lastName uniqueId jobRole highestQualification caste subCommunity city state height maritalStatus dob gender')
        .sort({ date: -1 });

        // Hardcode a permanent lock on sensitive fields just in case
        const formattedRequests = requests.map(req => {
            const senderData = req.senderId ? req.senderId.toObject() : {};
            senderData.mobileNumber = "Admin Managed";
            senderData.email = "Admin Managed";
            senderData.photos = []; 
            
            return { ...req.toObject(), senderId: senderData };
        });

        res.json({ success: true, count: formattedRequests.length, data: formattedRequests });
    } catch (e) {
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// 2. Get "Sent" Interests (Requests I sent to OTHERS)
app.get("/api/user/interests/sent", verifyUser, async (req, res) => {
    try {
        const sentRequests = await Interest.find({ senderId: req.userId })
        // POPULATE ALL DASHBOARD FIELDS
        .populate('receiverId', 'firstName lastName uniqueId jobRole highestQualification caste subCommunity city state height maritalStatus dob gender') 
        .sort({ date: -1 });

        const formattedRequests = sentRequests.map(req => {
            // Keep the structure identical to 'received' to make frontend easy
            const receiverData = req.receiverId ? req.receiverId.toObject() : {};
            receiverData.mobileNumber = "Admin Managed";
            receiverData.email = "Admin Managed";
            receiverData.photos = []; 
            
            return { ...req.toObject(), receiverId: receiverData };
        });

        res.json({ success: true, count: formattedRequests.length, data: formattedRequests });
    } catch (e) {
        res.status(500).json({ success: false, message: "Server Error" });
    }
});
                

// ====================================================================
// UPDATED API 1: Advanced List (Fixed Filtering & Agent Populating)
// ====================================================================
app.get("/api/admin/users/advanced", verifyAdmin, async (req, res) => {
    try {
        const { search, referralType, status, page = 1, limit = 10 } = req.query;
        
        const query = {};

        // 1. Search Logic
        if (search) {
            query.$or = [
                { firstName: { $regex: search, $options: "i" } },
                { lastName: { $regex: search, $options: "i" } },
                { email: { $regex: search, $options: "i" } },
                { mobileNumber: { $regex: search, $options: "i" } },
                { uniqueId: { $regex: search, $options: "i" } }
            ];
        }

        // 2. Referral Filter (FIXED)
        if (referralType === 'agent') {
            // Must have an agent ID
            query.referredByAgentId = { $ne: null }; 
        } else if (referralType === 'self') {
            // Must NOT have an agent ID (Check for null OR field does not exist)
            query.$or = [
                { referredByAgentId: null }, 
                { referredByAgentId: { $exists: false } }
            ];
        }

        // 3. Status Filter
        if (status === 'blocked') query.isActive = false;
        if (status === 'active') query.isActive = true;
        if (status === 'pending') query.isApproved = false;

        // 4. Execute with Pagination & Population
        const users = await User.find(query)
            .sort({ createdAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit)
            .select('-password')
            // *** THIS IS THE KEY FIX FOR AGENT DETAILS ***
            .populate('referredByAgentId', 'name agentCode mobile'); 

        const count = await User.countDocuments(query);

        res.json({ 
            success: true, 
            users, 
            totalPages: Math.ceil(count / limit), 
            currentPage: Number(page),
            totalUsers: count
        });

    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});
    




// ====================================================================
// MISSING API 2: Delete User (UPDATED WITH CLOUDINARY CLEANUP)
// ====================================================================
app.delete("/api/admin/users/:id", verifyAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        
        // 1. Find the user first (We need their data to get photo URLs)
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        // 2. DELETE PHOTOS FROM CLOUDINARY
        // Check if user has photos and loop through them
        if (user.photos && user.photos.length > 0) {
            const deletePromises = user.photos.map(imageUrl => {
                // Extract Public ID from URL
                // Example: https://res.cloudinary.com/.../matrimony_users/abc123.jpg
                // We need: "matrimony_users/abc123"
                
                const parts = imageUrl.split('/');
                const fileWithExt = parts.pop();       // "abc123.jpg"
                const folder = parts.pop();            // "matrimony_users"
                const publicId = `${folder}/${fileWithExt.split('.')[0]}`; 

                return cloudinary.uploader.destroy(publicId);
            });

            // Wait for all Cloudinary deletions to finish
            await Promise.all(deletePromises);
        }

        // 3. Optional: Delete related payments/interests (Cleanup database references)
        // await PaymentRegistration.deleteMany({ userId });
        // await Interest.deleteMany({ $or: [{ senderId: userId }, { receiverId: userId }] });

        // 4. Finally, Delete User from MongoDB
        await User.findByIdAndDelete(userId);

        res.json({ success: true, message: "User and their photos deleted permanently" });

    } catch (e) {
        console.error("Delete User Error:", e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});



// ====================================================================
// I. AGENT DASHBOARD OPERATIONS (FIXED)
// ====================================================================

// 1. Get Agent Dashboard Stats
app.get("/api/agent/dashboard/stats", verifyAgent, async (req, res) => {
    try {
        // Find users referred by THIS agent
        const myUsers = await User.find({ referredByAgentId: req.agentId });
        
        // Calculate Stats
        const totalReferrals = myUsers.length;
        const paidReferrals = myUsers.filter(u => u.isPaidMember).length;
        const pendingApprovals = myUsers.filter(u => !u.isApproved).length;

        res.json({
            success: true,
            stats: {
                totalReferrals,
                paidReferrals,
                pendingApprovals
            }
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// 2. Get "My Users" List (Detailed, No Photos, No Address)
app.get("/api/agent/users", verifyAgent, async (req, res) => {
    try {
        const users = await User.find({ referredByAgentId: req.agentId })
            // Exclude: password, photos, and address fields (country, state, city)
            .select('-password -photos -country -state -city -fcmToken') 
            .sort({ createdAt: -1 });

        res.json({ success: true, count: users.length, users });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});


                    
// 3. Register a User (Manual Entry by Agent) - Includes Pending Data Staging
app.post("/api/agent/register-user", verifyAgent, async (req, res) => {
    try {
        const data = req.body; 
        const agent = await Agent.findById(req.agentId);

        if (!agent) {
            return res.status(404).json({ success: false, message: "Agent not found" });
        }

        // 1. Check if user already exists
        const existingUser = await User.findOne({ 
            $or: [{ email: data.email }, { mobileNumber: data.mobileNumber }] 
        });

        if (existingUser) {
            return res.status(400).json({ success: false, message: "User with this Email or Mobile already exists" });
        }

        // 2. Prepare Data
        const uniqueId = await generateUserId(data.state); // Generates ID based on State
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(data.password, salt);

        // Sanitize height & gothra just in case agent frontend sends empty strings
        const safeHeight = (data.height && data.height !== '') ? Number(data.height) : undefined;
        const safeGothra = data.gothra ? data.gothra.trim() : undefined;

        // 3. Create User Object 
        const user = new User({
            profileFor: data.profileFor,
            gender: data.gender,
            firstName: data.firstName,
            lastName: data.lastName,
            dob: data.dob,
            religion: data.religion,
            community: data.community, 
            caste: data.subCommunity || data.caste, // Sync subCommunity and caste
            subCommunity: data.subCommunity,
            country: data.country,
            state: data.state,
            city: data.city,
            maritalStatus: data.maritalStatus,
            height: safeHeight, 
            diet: data.diet,
            highestQualification: data.highestQualification,
            collegeName: data.collegeName,
            workType: data.workType, 
            jobRole: data.jobRole,
            companyName: data.companyName,
            annualIncome: data.annualIncome,
            email: data.email,
            mobileNumber: data.mobileNumber,
            password: hashedPassword,
            uniqueId: uniqueId,
            isActive: true, 
            isApproved: false, 
            isPaidMember: false,
            gothra: safeGothra,
            residentsIn: data.residentsIn,
            referredByAgentId: agent._id,
            referredByAgentName: agent.name,
            referralType: 'manual' ,
            nri: data.nri
        });

        // 4. Save to DB
        await user.save();

        // --- THE MAGIC FIX: Reuse the global helper and AWAIT it ---
        await checkAndStageNewMasterData(user._id, data);

        // 5. PREPARE EMAILS
        const userWelcomeContent = generateEmailTemplate(
            "Welcome to KalyanaShobha",
            `<p>Dear ${user.firstName},</p>
             <p>Your profile has been created by our agent <strong>${agent.name}</strong>.</p>
             <p><strong>Profile ID:</strong> ${user.uniqueId}</p>
             <p><strong>Email :</strong> ${user.email}</p>
             <p><strong>Login Password:</strong> ${data.password}</p>
             <p>Please login to your dashboard to view matches.</p>`
        );

        const agentNotificationContent = generateEmailTemplate(
            "New User Registered Successfully",
            `<p>Dear ${agent.name},</p>
             <p>You have successfully registered a new user manually on KalyanaShobha.</p>
             <p><strong>User Name:</strong> ${user.firstName} ${user.lastName}</p>
             <p><strong>Profile ID:</strong> ${user.uniqueId}</p>
             <p>This user has been added to your referral list and you can track their status in your agent dashboard.</p>`
        );

        // --- NEW: ADMIN NOTIFICATION CONTENT ---
        const adminAlertContent = generateEmailTemplate(
            "Agent Registration Alert",
            `<p>An agent has manually registered a new user on the platform.</p>
             <p><strong>Agent Name:</strong> ${agent.name}</p>
             <table style="width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px;">
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd; width: 40%; color: #666;"><strong>User Name:</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;">${user.firstName} ${user.lastName}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Profile ID:</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>${user.uniqueId}</strong></td>
                </tr>
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Email:</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;">${user.email}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Mobile:</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;">${user.mobileNumber}</td>
                </tr>
             </table>
             <div style="margin-top: 20px; text-align: center;">
                <a href="https://kalyanashobha.in/admin" style="background-color: #2c3e50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; font-size: 14px;">Go to Admin Dashboard</a>
             </div>`
        );

        // 6. SEND EMAILS (Parallel & Awaited)
        try {
            await Promise.all([
                sendMail({ to: user.email, subject: "Profile Created via Agent", html: userWelcomeContent }),
                sendMail({ to: agent.email, subject: `Registration Successful: ${user.firstName}`, html: agentNotificationContent }),
                // --- NEW: SEND TO ADMIN ---
                sendMail({ to: EMAIL_USER, subject: `New Agent Registration: ${user.uniqueId}`, html: adminAlertContent })
            ]);
        } catch (emailError) {
            console.error("Email Sending Failed:", emailError);
        }

        res.json({ success: true, message: "User registered successfully under your referral." });

    } catch (e) {
        console.error("Agent Reg Error:", e);
        res.status(500).json({ success: false, message: e.message });
    }
});
            
        



// 4. View Membership Payments (Only for My Users)
app.get("/api/agent/payments/registrations", verifyAgent, async (req, res) => {
    try {
        // 1. Get IDs of users referred by this agent
        const myUsers = await User.find({ referredByAgentId: req.agentId }).select('_id');
        const userIds = myUsers.map(u => u._id);

        if (userIds.length === 0) {
            return res.json({ success: true, count: 0, payments: [] });
        }

        // 2. Find payments made by these users
        const payments = await PaymentRegistration.find({ userId: { $in: userIds } })
            .populate('userId', 'firstName lastName uniqueId mobileNumber') // Show User Details
            .sort({ date: -1 });

        res.json({ success: true, count: payments.length, payments });
    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// 5. View Interest Payments/Activities (Only for My Users)
app.get("/api/agent/payments/interests", verifyAgent, async (req, res) => {
    try {
        // 1. Get IDs of users referred by this agent
        const myUsers = await User.find({ referredByAgentId: req.agentId }).select('_id');
        const userIds = myUsers.map(u => u._id);

        if (userIds.length === 0) {
            return res.json({ success: true, count: 0, payments: [] });
        }

        // 2. Find Interest Payments where the SENDER is one of the agent's users
        // This shows money spent by the Agent's clients
        const payments = await PaymentInterest.find({ senderId: { $in: userIds } })
            .populate('senderId', 'firstName lastName uniqueId')   // My User
            .populate('receiverId', 'firstName lastName uniqueId') // Who they want to contact
            .sort({ date: -1 });

        res.json({ success: true, count: payments.length, payments });
    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});


// ====================================================================
// NEW: DEDICATED RESTRICT/BLOCK USER API
// ====================================================================

app.post("/api/admin/users/restrict", verifyAdmin, async (req, res) => {
    try {
        const { userId, restrict } = req.body; // restrict: true = BLOCK, false = UNBLOCK

        if (!userId) {
            return res.status(400).json({ success: false, message: "User ID is required" });
        }

        const user = await User.findById(userId);
        
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        // Logic: If restricting, set isActive to false. If unrestricting, set isActive to true.
        user.isActive = !restrict; 
        
        await user.save();

        const actionWord = restrict ? "Restricted (Blocked)" : "Unrestricted (Active)";
        
        // Optional: Notify User
        if (restrict) {
            const emailContent = generateEmailTemplate(
                "Account Access Restricted",
                `<p>Your account access has been restricted by the administrator.</p>
                 <p>You will no longer be able to log in.</p>
                 <p>Please contact support if you believe this is an error.</p>`
            );
            await sendMail({ 
    to: user.email, 
    subject: "Account Status Update", 
    html: emailContent,
    fromEmail: `"KalyanaShobha Admin" <admin@kalyanashobha.in>`
});
            
        } else {
             const emailContent = generateEmailTemplate(
                "Account Access Restored",
                `<p>Your account restriction has been removed.</p>
                 <p>You can now log in to your dashboard.</p>`
            );
            await sendMail({ 
    to: user.email, 
    subject: "Account Status Update", 
    html: emailContent,
    fromEmail: `"KalyanaShobha Admin" <admin@kalyanashobha.in>`
});

        }

        res.json({ success: true, message: `User successfully ${actionWord}` });

    } catch (e) {
        console.error("Restriction API Error:", e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});


// ====================================================================
// UNIFIED DASHBOARD & SEARCH API (With Interest Status Check)
// ====================================================================
app.post("/api/user/dashboard/feed", verifyUser, async (req, res) => {
    try {
        // 1. Get Current User & Status
        const currentUser = await User.findById(req.userId);
        if (!currentUser) return res.status(404).json({ success: false, message: "User not found" });

        const isViewerPremium = currentUser.isPaidMember;
        const targetGender = currentUser.gender === 'Male' ? 'Female' : 'Male';

        // 2. FETCH INTERACTIONS (The "Check First" Logic)
        const interactions = await Interest.find({
            $or: [{ senderId: req.userId }, { receiverId: req.userId }]
        });

        // 3. Create Status Map
        const statusMap = {};
        interactions.forEach(inter => {
            const otherId = inter.senderId.toString() === req.userId.toString() 
                ? inter.receiverId.toString() 
                : inter.senderId.toString();
            statusMap[otherId] = inter.status; 
        });

        // 4. Destructure Filters from Body (ADDED COMPLEXION)
        const {
            searchId,
            minAge, maxAge,
            minHeight, maxHeight,
            minSalary,
            education,
            community, 
            subCommunity,
            maritalStatus,
            occupation,
            // Location / Astro Filters
            country,
            state,
            city,
            diet,
            motherTongue,
            star,
            pada,
            complexion // <--- ADDED THIS
        } = req.body;

        // 5. CHECK PERMISSIONS (ADDED COMPLEXION)
        const hasFilters = searchId || minAge || maxAge || minHeight || maxHeight || minSalary || education || community || subCommunity || maritalStatus || occupation || country || state || city || diet || motherTongue || star || pada || complexion; // <--- ADDED THIS

        if (hasFilters && !isViewerPremium) {
            return res.status(403).json({ 
                success: false, 
                message: "Search is a Premium feature. Please upgrade to filter matches." 
            });
        }

        // 6. Build Base Query
        let query = {
            gender: targetGender,
            isApproved: true,
            isActive: true,
            _id: { $ne: req.userId }, 
            isPaidMember: true 
        };

        // 7. Apply Search Filters
        if (hasFilters) {
            if (searchId) {
                query.uniqueId = { $regex: searchId, $options: 'i' };
            } else {
                if (minAge || maxAge) {
                    const today = new Date();
                    query.dob = {};
                    if (maxAge) query.dob.$gte = new Date(new Date().setFullYear(today.getFullYear() - maxAge));
                    if (minAge) query.dob.$lte = new Date(new Date().setFullYear(today.getFullYear() - minAge));
                }
                if (minHeight || maxHeight) {
                    query.height = {};
                    if (minHeight) query.height.$gte = parseFloat(minHeight);
                    if (maxHeight) query.height.$lte = parseFloat(maxHeight);
                }
                if (minSalary) {
                    // Adjust this based on how you store salary (number vs string)
                    query.annualIncome = { $regex: minSalary, $options: 'i' }; 
                }
                if (education) query.highestQualification = education;
                if (maritalStatus) query.maritalStatus = maritalStatus;
                if (community) query.community = community; 
                if (subCommunity) query.$or = [{ caste: subCommunity }, { subCommunity: subCommunity }];
                if (occupation) query.jobRole = { $regex: occupation, $options: 'i' };

                // --- NEW FILTERS ADDED TO DB QUERY ---
                if (country) query.country = country;
                if (state) query.state = state;
                if (city) query.city = city;
                if (diet) query.diet = diet;
                if (motherTongue) query['astrologyDetails.motherTongue'] = motherTongue;
                if (star) query['astrologyDetails.star'] = star;
                if (pada) query['astrologyDetails.pada'] = pada;
                if (complexion) query['astrologyDetails.complexion'] = complexion; // <--- ADDED THIS
            }
        }

        // 8. Execute Query
        let profilesQuery = User.find(query)
            .select('firstName lastName dob highestQualification community caste subCommunity city state maritalStatus jobRole uniqueId photos height annualIncome')
            .sort({ createdAt: -1 });

        // Limit Free Users
        if (!isViewerPremium) {
            profilesQuery = profilesQuery.limit(2);
        }

        const profiles = await profilesQuery;
        const totalMatches = await User.countDocuments(query);

        // 9. Format Data
        const formattedData = profiles.map(p => {
            let age = "N/A";
            if (p.dob) {
                const diff = Date.now() - new Date(p.dob).getTime();
                const ageDate = new Date(diff);
                age = Math.abs(ageDate.getUTCFullYear() - 1970);
            }

            const currentStatus = statusMap[p._id.toString()] || null;

            return {
                id: p._id,
                uniqueId: p.uniqueId,
                name: `${p.firstName} ${p.lastName}`,
                age: age,
                occupation: p.jobRole || "Not Specified",
                education: p.highestQualification || "Not Specified",
                community: p.community || p.caste || "Not Specified",
                subCommunity: p.subCommunity || "Not Specified",
                location: `${p.city}, ${p.state}`,
                status: p.maritalStatus,
                height: p.height,
                salary: p.annualIncome,
                photo: p.photos && p.photos.length > 0 ? p.photos[0] : null,
                interestStatus: currentStatus
            };
        });

        res.json({ 
            success: true, 
            isPremium: isViewerPremium,
            count: formattedData.length,
            totalAvailable: totalMatches, 
            data: formattedData 
        });

    } catch (e) {
        console.error("Unified Feed Error:", e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});
            
                
  
                                                                          


// ====================================================================
// SIMPLE CREATE ADMIN (FOR POSTMAN)
// ====================================================================
app.post("/api/admin/create-simple", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // 1. Check if data is present
        if (!username || !email || !password) {
            return res.status(400).json({ success: false, message: "Please provide username, email, and password." });
        }

        // 2. Check if this email is already an admin
        const existingAdmin = await Admin.findOne({ email });
        if (existingAdmin) {
            return res.status(400).json({ success: false, message: "Admin with this email already exists." });
        }

        // 3. Encrypt the password (REQUIRED for login to work)
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // 4. Save the new Admin
        const newAdmin = new Admin({
            username: username,
            email: email,
            password: hashedPassword,
            role: "SuperAdmin" // Sets them as Super Admin automatically
        });

        await newAdmin.save();

        res.json({ 
            success: true, 
            message: "Super Admin Created Successfully!",
            adminId: newAdmin._id 
        });

    } catch (e) {
        console.error("Create Admin Error:", e);
        res.status(500).json({ success: false, message: e.message });
    }
});
// --- HELPER: GENERATE CERTIFICATE HTML ---
const generateCertificateHTML = (user) => {
    // Format Date
    const signedDate = user.termsAcceptedAt 
        ? new Date(user.termsAcceptedAt).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })
        : "Not Recorded";

    return `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Acceptance Certificate - ${user.uniqueId}</title>
        <style>
            body { font-family: 'Times New Roman', serif; background-color: #f9f9f9; padding: 40px; }
            .certificate-container {
                max-width: 800px; margin: 0 auto; background: white; padding: 50px;
                border: 10px solid #2c3e50; position: relative;
            }
            .header { text-align: center; margin-bottom: 40px; }
            .header h1 { font-size: 36px; color: #c0392b; margin: 0; text-transform: uppercase; letter-spacing: 2px; }
            .header h3 { font-size: 18px; color: #555; margin-top: 10px; font-weight: normal; }
            .content { font-size: 16px; line-height: 1.8; color: #333; margin-bottom: 50px; text-align: justify; }
            .details-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            .details-table td { padding: 8px; border-bottom: 1px solid #eee; }
            .signature-section { display: flex; justify-content: space-between; margin-top: 60px; }
            .sig-box { text-align: center; width: 45%; }
            .sig-img { max-height: 80px; display: block; margin: 0 auto 10px; }
            .line { border-top: 2px solid #333; margin-top: 10px; }
            .footer { text-align: center; font-size: 10px; color: #999; margin-top: 40px; border-top: 1px solid #ddd; padding-top: 10px; }
        </style>
    </head>
    <body>
        <div class="certificate-container">
            <div class="header">
                <h1>Certificate of Acceptance</h1>
                <h3>KalyanaShobha Matrimony Services</h3>
            </div>

            <div class="content">
                <p>This document certifies that the user identified below has successfully registered with KalyanaShobha and has explicitly agreed to the <strong>Terms & Conditions</strong> and <strong>Privacy Policy</strong> of the platform.</p>
                
                <p>By providing their digital signature, the user has confirmed the accuracy of their profile information and consented to identity verification protocols.</p>

                <table class="details-table">
                    <tr><td><strong>User Name:</strong></td><td>${user.firstName} ${user.lastName}</td></tr>
                    <tr><td><strong>Profile ID:</strong></td><td>${user.uniqueId}</td></tr>
                    <tr><td><strong>Email Address:</strong></td><td>${user.email}</td></tr>
                    <tr><td><strong>Mobile Number:</strong></td><td>${user.mobileNumber}</td></tr>
                    <tr><td><strong>Acceptance Date:</strong></td><td>${signedDate}</td></tr>
                    <tr><td><strong>IP Address:</strong></td><td>${user.termsAcceptedIP || "N/A"}</td></tr>
                </table>
            </div>

            <div class="signature-section">
                <div class="sig-box">
                    <img src="${user.digitalSignature}" alt="User Signature" class="sig-img" />
                    <div class="line"></div>
                    <p><strong>${user.firstName} ${user.lastName}</strong><br>Electronically Signed</p>
                </div>
                <div class="sig-box">
                    <h2 style="margin:0; color: #2c3e50; font-family: 'Brush Script MT', cursive; font-size: 30px;">KalyanaShobha</h2>
                    <div class="line"></div>
                    <p><strong>Authorized System</strong><br>Verification Authority</p>
                </div>
            </div>

            <div class="footer">
                <p>Certificate Generated on: ${new Date().toLocaleString()}</p>
                <p>Document ID: ${user._id} | This is a computer-generated document.</p>
            </div>
        </div>
    </body>
    </html>
    `;
};

// ====================================================================
// GET USER CERTIFICATE (HTML View)
// ====================================================================
app.get("/api/admin/user-certificate/:id", verifyAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        
        if (!user) {
            return res.status(404).send("User not found");
        }

        if (!user.digitalSignature) {
            return res.status(400).send("User has not signed digitally.");
        }

        // Generate the HTML
        const html = generateCertificateHTML(user);

        // Send as HTML page (Browser will render it, Admin can Print/Save as PDF)
        res.send(html);

    } catch (e) {
        console.error("Certificate Error:", e);
        res.status(500).send("Server Error generating certificate");
    }
});


// ====================================================================
// UNIVERSAL ADD COMMUNITY API (Handles Single, Multiple & Sub-Communities)
// ====================================================================
app.post("/api/admin/add-community", verifyAdmin, async (req, res) => {
    try {
        let { community, subCommunity } = req.body;

        if (!community) {
            return res.status(400).json({ success: false, message: "Community name is required" });
        }

        // --- SCENARIO 1: Multiple Communities (Array) ---
        // Input: { "community": ["Hindu", "Muslim", "Sikh"] }
        // Logic: Creates them all at once. Ignores 'subCommunity' to avoid confusion.
        if (Array.isArray(community)) {
            const operations = community.map(name => ({
                updateOne: {
                    filter: { name: name.trim() },
                    update: { $setOnInsert: { name: name.trim(), subCommunities: [] } },
                    upsert: true // Create if it doesn't exist, Do nothing if it does
                }
            }));
            
            await Community.bulkWrite(operations);
            return res.json({ success: true, message: `Successfully processed ${community.length} communities.` });
        }

        // --- SCENARIO 2: Single Community (String) ---
        // Input: { "community": "Hindu", "subCommunity": "Brahmin" } OR { "community": "Hindu", "subCommunity": ["Brahmin", "Yadav"] }
        if (typeof community === 'string') {
            const communityName = community.trim();
            let subCommunitiesToAdd = [];

            // Normalize subCommunity to an Array (handles string, array, or null)
            if (subCommunity) {
                subCommunitiesToAdd = Array.isArray(subCommunity) 
                    ? subCommunity.map(s => s.trim()) 
                    : [subCommunity.trim()];
            }

            // The Magic Query: "Upsert"
            // 1. Finds the community by name.
            // 2. If found -> Adds new sub-communities (without duplicates).
            // 3. If NOT found -> Creates it AND adds the sub-communities.
            const updatedCommunity = await Community.findOneAndUpdate(
                { name: communityName },
                { 
                    $setOnInsert: { name: communityName }, // Runs only if creating new
                    $addToSet: { subCommunities: { $each: subCommunitiesToAdd } } // Runs always (adds unique subs)
                },
                { new: true, upsert: true }
            );

            return res.json({ 
                success: true, 
                message: "Community saved successfully", 
                data: updatedCommunity 
            });
        }

        return res.status(400).json({ success: false, message: "Invalid format" });

    } catch (e) {
        console.error("Add Community Error:", e);
        res.status(500).json({ success: false, message: e.message });
    }
});

// 2. Add Sub-Communities (SECURED & SAFER)
app.post("/api/admin/add-sub-community", verifyAdmin, async (req, res) => {
    try {
        let { communityName, subCommunities } = req.body; 

        if (!communityName || !subCommunities) {
             return res.status(400).json({ success: false, message: "Community Name and Sub-Communities are required." });
        }

        // --- SAFETY FIX: Ensure it is always an array ---
        // If user sends "Brahmin", we convert it to ["Brahmin"]
        const subCommunitiesArray = Array.isArray(subCommunities) 
            ? subCommunities 
            : [subCommunities];

        // Use findOneAndUpdate to append new data
        const updated = await Community.findOneAndUpdate(
            { name: communityName },
            { $addToSet: { subCommunities: { $each: subCommunitiesArray } } },
            { new: true }
        );

        if (!updated) {
            return res.status(404).json({ success: false, message: "Main Community not found. Create it first." });
        }

        res.json({ success: true, message: "Sub-communities added", data: updated });
    } catch (e) {
        console.error("Add SubCommunity Error:", e);
        res.status(500).json({ success: false, message: e.message });
    }
});



// ====================================================================
// PUBLIC: GET COMMUNITY DROPDOWN DATA
// ====================================================================

// 1. Get ALL Communities (Names + Sub-communities)
app.get("/api/public/get-all-communities", async (req, res) => {
    try {
        // ADD .sort({ order: 1 }) HERE
        const communities = await Community.find().sort({ order: 1 }).select('name subCommunities order').lean();

        res.json({ success: true, count: communities.length, data: communities });
    } catch (e) {
        res.status(500).json({ success: false, message: "Server Error" });
    }
});


// 2. Get Sub-Communities for a Specific Community
// Usage: Call this if you prefer to load data ONLY after the user selects a Religion.
// Example URL: /api/public/get-sub-community/Hindu
app.get("/api/public/get-sub-community/:name", async (req, res) => {
    try {
        const communityName = req.params.name;
        
        // Find the community by name (Case-insensitive search is better for public APIs)
        const community = await Community.findOne({ 
            name: { $regex: new RegExp(`^${communityName}$`, 'i') } 
        });

        if (!community) {
            return res.status(404).json({ success: false, message: "Community not found" });
        }

        res.json({
            success: true,
            community: community.name,
            subCommunities: community.subCommunities.sort() // Return alphabetically sorted
        });

    } catch (e) {
        console.error("Get SubCommunity Error:", e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});


// Submit a new lead for a vendor
app.post("/api/user/vendor-lead", async (req, res) => {
    try {
        const { vendorId, name, phone, email, weddingDate, guestCount, message } = req.body;

        // 1. Basic Validation
        if (!vendorId || !name || !phone || !message) {
            return res.status(400).json({ success: false, message: "Name, phone, and message are required." });
        }

        // 2. Save Lead to Database
        const newLead = new VendorLead({ 
            vendorId, name, phone, email, weddingDate, guestCount, message 
        });
        await newLead.save();

        // 3. Fetch Vendor Details (To get their Name AND Email)
        const vendor = await Vendor.findById(vendorId);
        const vendorName = vendor ? vendor.businessName : "Unknown Vendor";
        const vendorEmail = vendor ? vendor.email : null; // Get the vendor's email

        // 4. Prepare Admin Alert Content
        const adminAlertContent = generateEmailTemplate(
            "New Premium Vendor Lead",
            `<p>A new lead has been submitted for <strong>${vendorName}</strong>.</p>
             <table style="width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px;">
                <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; width: 30%; color: #666;"><strong>Name:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${name}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Phone:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${phone}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Email:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${email || 'N/A'}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Date:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${weddingDate || 'N/A'}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Guests:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${guestCount || 'N/A'}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Message:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${message}</td></tr>
             </table>
             <div style="margin-top: 20px; text-align: center;">
                <a href="https://kalyanashobha-admin.vercel.app" style="background-color: #2c3e50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; font-size: 14px;">Open Admin Dashboard</a>
             </div>`
        );

        const emailPromises = [];

        // Add Admin Email to the queue
        emailPromises.push(
            sendMail({ 
                to: EMAIL_USER, 
                subject: `New Lead: ${vendorName}`, 
                html: adminAlertContent 
            })
        );

        // 5. Prepare and queue Vendor Email Content (If vendor has an email)
        if (vendorEmail) {
            const vendorAlertContent = generateEmailTemplate(
                "New Customer Inquiry - KalyanaShobha",
                `<p>Hello <strong>${vendorName}</strong> Team,</p>
                 <p>You have received a new business inquiry through KalyanaShobha. Here are the customer's details:</p>
                 <table style="width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px;">
                    <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; width: 30%; color: #666;"><strong>Customer Name:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${name}</td></tr>
                    <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Phone:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${phone}</td></tr>
                    <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Email:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${email || 'N/A'}</td></tr>
                    
                    
                    <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Message:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${message}</td></tr>
                 </table>
                 <p style="margin-top: 20px;">Please reach out to the customer directly at your earliest convenience to discuss their requirements.</p>`
            );

            emailPromises.push(
                sendMail({ 
                    to: vendorEmail, 
                    subject: "New Customer Inquiry from KalyanaShobha", 
                    html: vendorAlertContent 
                })
            );
        }

        // Send all emails in parallel
        try {
            await Promise.all(emailPromises);
            console.log("Vendor lead emails sent successfully.");
        } catch (emailError) {
            console.error("Failed to send vendor lead emails:", emailError);
            // We don't fail the request if emails fail, the lead is already saved in DB
        }

        // 6. Send Success Response to Frontend
        res.json({ 
            success: true, 
            message: "Request sent successfully! Our concierge team will contact you shortly." 
        });

    } catch (error) {
        console.error("Vendor Lead Submit Error:", error);
        res.status(500).json({ success: false, message: "Server Error while submitting lead" });
    }
});






// Admin: Update Vendor Lead Status
app.put("/api/admin/vendor-leads/:id/status", verifyAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        const validStatuses = ['New', 'Contacted', 'Forwarded', 'Closed'];
        
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ success: false, message: "Invalid status" });
        }

        const lead = await VendorLead.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true }
        );

        if (!lead) {
            return res.status(404).json({ success: false, message: "Lead not found" });
        }

        res.json({ success: true, message: `Lead marked as ${status}`, data: lead });
    } catch (error) {
        console.error("Update Lead Status Error:", error);
        res.status(500).json({ success: false, message: "Server Error updating lead status" });
    }
});

app.post("/api/user/help-center/submit", verifyUser, uploadIssue.single("screenshot"), async (req, res) => {
    try {
        const { subject, summary } = req.body;
        const user = await User.findById(req.userId);

        if (!subject || !summary) {
            return res.status(400).json({ success: false, message: "Subject and summary are required." });
        }

        // Get Cloudinary URL if a screenshot was uploaded
        const screenshotUrl = req.file ? req.file.path : null;

        const issue = new HelpIssue({
            userId: req.userId,
            subject,
            summary,
            screenshotUrl
        });
        
        await issue.save();

        // Send Email Alert to Admin
        const adminEmailContent = generateEmailTemplate(
            "New Help Center Ticket",
            `<p>User <strong>${user.firstName} ${user.lastName}</strong> (${user.uniqueId}) has reported a new issue.</p>
             <p><strong>Subject:</strong> ${subject}</p>
             <p><strong>Summary:</strong> ${summary}</p>
             ${screenshotUrl ? `<p><a href="${screenshotUrl}" target="_blank" style="color: #2c3e50; font-weight: bold;">View Attached Screenshot</a></p>` : "<p><em>No screenshot provided.</em></p>"}
             <div style="margin-top: 20px; text-align: center;">
                <a href="https://kalyanashobha-admin.vercel.app" style="background-color: #2c3e50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">Open Admin Dashboard</a>
             </div>`
        );

        // Send to your admin email
        await sendMail({ 
            to: EMAIL_USER,
            subject: `New Issue Reported: ${subject}`, 
            html: adminEmailContent 
        });

        res.json({ success: true, message: "Issue submitted successfully. Our team will look into it." });

    } catch (error) {
        console.error("Help Center Submit Error:", error);
        res.status(500).json({ success: false, message: "Server Error while submitting issue" });
    }
});

// A. Fetch Issues for Admin Dashboard
app.get("/api/admin/help-center/issues", verifyAdmin, async (req, res) => {
    try {
        const issues = await HelpIssue.find()
            .populate('userId', 'firstName lastName uniqueId email mobileNumber')
            .sort({ date: -1 }); // Newest first

        res.json({ success: true, count: issues.length, data: issues });
    } catch (error) {
        res.status(500).json({ success: false, message: "Server Error fetching issues" });
    }
});

// B. Admin Resolves the Issue
app.post("/api/admin/help-center/resolve", verifyAdmin, async (req, res) => {
    try {
        const { issueId, adminReply } = req.body;

        if (!issueId || !adminReply) {
            return res.status(400).json({ success: false, message: "Issue ID and Admin Reply are required." });
        }

        const issue = await HelpIssue.findById(issueId).populate('userId');
        if (!issue) {
            return res.status(404).json({ success: false, message: "Issue not found." });
        }

        // Update status in DB
        issue.status = 'Resolved';
        await issue.save();

        // Send Resolution Email to User
        const userEmailContent = generateEmailTemplate(
            "Support Ticket Resolved",
            `<p>Dear ${issue.userId.firstName},</p>
             <p>Your recent support ticket regarding "<strong>${issue.subject}</strong>" has been reviewed and resolved by our team.</p>
             <div style="background-color: #f9f9f9; padding: 15px; border-left: 4px solid #2c3e50; margin: 20px 0;">
                <p style="margin: 0; color: #333;"><strong>Admin Reply:</strong><br>${adminReply}</p>
             </div>
             <p>If you require further assistance, please feel free to submit a new ticket from your dashboard.</p>`
        );

        await sendMail({ 
            to: issue.userId.email, 
            subject: `Resolved: ${issue.subject}`, 
            html: userEmailContent 
        });

        res.json({ success: true, message: "Issue resolved and user notified successfully." });

    } catch (error) {
        console.error("Resolve Issue Error:", error);
        res.status(500).json({ success: false, message: "Server Error resolving issue" });
    }
});

app.post("/api/interest/send", verifyUser, async (req, res) => {
    try {
        const { receiverId } = req.body;

        // 1. Fetch user to ensure they are allowed to send requests
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        // User must be a paid member to send interests now
        if (!user.isPaidMember) {
            return res.status(403).json({ success: false, message: "Please purchase a membership to send interests." });
        }

        // 2. Duplicate Check
        const existingInterest = await Interest.findOne({
            senderId: req.userId,
            receiverId: receiverId,
            status: { $ne: 'Rejected' } 
        });

        if (existingInterest) {
            let msg = "Request already exists.";
            if (existingInterest.status === 'Finalized') msg = "The Admin is already managing this connection.";
            if (existingInterest.status === 'Declined') msg = "This user has previously declined your request.";
            return res.json({ success: false, message: msg, currentStatus: existingInterest.status });
        }

        // 3. Create Interest Record directly into Phase 1
        const interest = new Interest({
            senderId: req.userId, 
            receiverId, 
            status: "PendingAdminPhase1"
        });
        await interest.save();

        // 4. Alert the Admin
        const adminEmailContent = generateEmailTemplate(
            "New Interest Request (Phase 1)",
            `<p><strong>${user.firstName}</strong> (${user.uniqueId}) wants to connect with a profile.</p>
             <p>Please log in to the Admin Dashboard to review and forward the request to the receiver.</p>`
        );

        sendMail({ to: EMAIL_USER, subject: "Admin Alert: New Interest Phase 1", html: adminEmailContent });

        res.json({ success: true, message: "Interest request sent to Admin for approval." });

    } catch (e) {
        console.error("Interest Send Error:", e);
        return res.status(500).json({ success: false, error: e.message });
    }
});

// ====================================================================
// NEW ADMIN WORKFLOW: Get Interests for Phase 1 & Phase 2
// ====================================================================

app.get("/api/admin/interest/workflow", verifyAdmin, async (req, res) => {
    try {
        const { status } = req.query; // e.g., 'PendingAdminPhase1' or 'PendingAdminPhase2'
        
        // We can fetch multiple statuses if we separate them by commas in the frontend
        let query = {};
        if (status) {
            query.status = { $in: status.split(',') }; 
        }

        const interests = await Interest.find(query)
            .populate('senderId', 'firstName lastName uniqueId mobileNumber email')
            .populate('receiverId', 'firstName lastName uniqueId mobileNumber email')
            .sort({ date: -1 });

        res.json({ success: true, count: interests.length, data: interests });

    } catch (e) {
        console.error("Admin Workflow Fetch Error:", e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// Admin Processes the Interest (Phase 1 Forwarding or Phase 2 Finalizing)
app.post("/api/admin/interest/process", verifyAdmin, async (req, res) => {
    try {
        const { interestId, action, phase } = req.body;
        
        const interest = await Interest.findById(interestId)
            .populate('senderId', 'firstName lastName email')
            .populate('receiverId', 'firstName lastName email');

        if (!interest) return res.status(404).json({ success: false, message: "Record not found" });

        if (phase === 1) {
            if (action === "approve") {
                interest.status = "PendingUser"; // Forward to Receiver
                await interest.save();

                // Notify Receiver
                const emailContent = generateEmailTemplate(
                    "New Match Request",
                    `<p>You have a new interest request waiting for your response.</p>
                     <p>Please log in to your dashboard to view the basic details and Accept or Decline.</p>`
                );
                sendMail({ to: interest.receiverId.email, subject: "New Interest Request", html: emailContent });
            } else {
                interest.status = "Rejected"; // Admin blocks it
                await interest.save();
            }
        } 
        else if (phase === 2) {
            if (action === "finalize") {
                interest.status = "Finalized"; // Admin has completed the offline connection
                await interest.save();
            }
        }

        res.json({ success: true, message: "Request processed successfully" });

    } catch (e) { 
        console.error("Admin Process Error:", e);
        res.status(500).json({ success: false, message: "Server Error" }); 
    }
});

// ====================================================================
// UNIVERSAL MASTER DATA APIs (State, Education, Occupation, etc.)
// ====================================================================
// 1. PUBLIC: Get options for a specific category (e.g., /api/public/master-data/State?parent=India)
app.get("/api/public/master-data/:category", async (req, res) => {
    try {
        const { category } = req.params;
        const { parent } = req.query; // Capture the parent query parameter

        let query = { category };

        // If a parent is requested, filter by it using a case-insensitive regex
        if (parent) {
            query.parentValue = { $regex: new RegExp(`^${escapeRegExp(parent)}$`, 'i') };
        } 
        // Optional strictly hierarchical rule: 
        // If they ask for City/State but don't provide a parent, you could return an empty array here to force frontend discipline, 
        // but for now, we'll let it fetch all if no parent is provided.

        const data = await MasterData.find(query)
            .sort({ order: 1 })
            .select('name subItems parentValue order')
            .lean();

        res.json({ success: true, count: data.length, data });
    } catch (e) {
        res.status(500).json({ success: false, message: "Server Error fetching master data" });
    }
});


// 2. ADMIN: Add a generic category item (Handles single, bulk, and sub-items)
app.post("/api/admin/master-data", verifyAdmin, async (req, res) => {
    try {
        // ADD parentValue to destructured body
        const { category, name, subItems, parentValue } = req.body;

        if (!category || !name) {
            return res.status(400).json({ success: false, message: "Category and Name are required" });
        }

        const safeParent = parentValue ? parentValue.trim() : null;

        // SCENARIO 1: Bulk Add
        if (Array.isArray(name)) {
            // Added 'index' to the map function
            const operations = name.map((val, index) => ({
                updateOne: {
                    filter: { category, name: val.trim(), parentValue: safeParent },
                    update: { 
                        $setOnInsert: { category, name: val.trim(), parentValue: safeParent, subItems: [] },
                        // Force update the order field based on the array position
                        $set: { order: index } 
                    },
                    upsert: true
                }
            }));
            await MasterData.bulkWrite(operations);
            return res.json({ success: true, message: `Bulk added ${name.length} items to ${category}.` });
        }

        // SCENARIO 2: Single Add / Append Sub-Items
        const itemName = name.trim();
        let subItemsToAdd = [];

        if (subItems) {
            subItemsToAdd = Array.isArray(subItems) ? subItems.map(s => s.trim()) : [subItems.trim()];
        }

        const updatedData = await MasterData.findOneAndUpdate(
            { category, name: itemName, parentValue: safeParent },
            { 
                $setOnInsert: { category, name: itemName, parentValue: safeParent },
                $addToSet: { subItems: { $each: subItemsToAdd } } 
            },
            { new: true, upsert: true }
        );

        res.json({ success: true, message: "Saved successfully", data: updatedData });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});




// 2. The concurrent helper for Extra Details
const checkAndStageExtraMasterData = async (userId, astrologyDetails) => {
    if (!astrologyDetails) return;

    const checkPromises = [];
    const fieldsToCheck = [
        { category: 'Moonsign', value: astrologyDetails.moonsign },
        { category: 'Star', value: astrologyDetails.star },
        { category: 'Pada', value: astrologyDetails.pada }, 
        { category: 'MotherTongue', value: astrologyDetails.motherTongue },
        { category: 'Complexion', value: astrologyDetails.complexion }
    ];

    for (const item of fieldsToCheck) {
        // Prevent stringified nulls, undefined, and empty spaces
        if (!item.value || item.value === 'null' || item.value === 'undefined' || item.value.trim() === '') {
            continue;
        }

        const val = item.value.trim();
        const safeRegex = escapeRegExp(val); // STOPS CRASHES!

        // Process each field concurrently
        const promise = MasterData.findOne({ category: item.category, name: new RegExp(`^${safeRegex}$`, 'i') })
            .then(async (exists) => {
                if (!exists) {
                    await PendingMasterData.updateOne(
                        { category: item.category, value: val }, 
                        { $setOnInsert: { status: 'Pending', submittedBy: userId } },
                        { upsert: true }
                    );
                }
            })
            .catch(err => console.error(`Failed to stage extra detail ${item.category}:`, err.message));

        checkPromises.push(promise);
    }

    // Execute all checks at once so Vercel doesn't time out
    await Promise.allSettled(checkPromises);
};


// 3. POST: Add or Update Astrology & Family details
app.post("/api/user/extra-details", async (req, res) => {
    try {
        const { 
            userId, 
            astrologyDetails, 
            familyDetails 
        } = req.body;

        if (!userId) {
            return res.status(400).json({ success: false, message: "User ID is required" });
        }

        // 1. Find the user and update their details
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            {
                $set: {
                    astrologyDetails: astrologyDetails,
                    familyDetails: familyDetails,
                    hasAstrologyAndFamilyDetails: true 
                }
            },
            { new: true } 
        );

        if (!updatedUser) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        // --- STAGING LOGIC: VERCEL FIX ---
        // We MUST use 'await' here so the server finishes pushing to PendingMasterData before sending the response
        await checkAndStageExtraMasterData(userId, astrologyDetails);

        res.json({ 
            success: true, 
            message: "Astrology and Family details updated successfully!",
            hasAstrologyAndFamilyDetails: updatedUser.hasAstrologyAndFamilyDetails
        });

    } catch (error) {
        console.error("Error updating extra details:", error);
        res.status(500).json({ success: false, message: error.message });
    }
});
                


// GET: Fetch Astrology & Family details
app.get("/api/user/extra-details/:userId", async (req, res) => {
    try {
        const { userId } = req.params;

        const user = await User.findById(userId).select('astrologyDetails familyDetails hasAstrologyAndFamilyDetails');

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        res.json({ 
            success: true, 
            hasAstrologyAndFamilyDetails: user.hasAstrologyAndFamilyDetails,
            astrologyDetails: user.astrologyDetails,
            familyDetails: user.familyDetails
        });

    } catch (error) {
        console.error("Error fetching extra details:", error);
        res.status(500).json({ success: false, message: error.message });
    }
});



// 3. ADMIN: Delete a Master Data entry
app.delete("/api/admin/master-data/:id", verifyAdmin, async (req, res) => {
    try {
        await MasterData.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: "Item deleted successfully" });
    } catch (e) {
        res.status(500).json({ success: false, message: "Failed to delete item" });
    }
});

// ====================================================================
// DELETE: Main Community
// ====================================================================
app.delete("/api/admin/community/:id", verifyAdmin, async (req, res) => {
    try {
        const deletedCommunity = await Community.findByIdAndDelete(req.params.id);
        
        if (!deletedCommunity) {
            return res.status(404).json({ success: false, message: "Community not found" });
        }
        
        res.json({ success: true, message: "Main community deleted successfully" });
    } catch (e) {
        console.error("Delete Community Error:", e);
        res.status(500).json({ success: false, message: "Failed to delete community" });
    }
});

// ====================================================================
// DELETE: Sub-Community
// ====================================================================
app.delete("/api/admin/community/:id/sub/:subName", verifyAdmin, async (req, res) => {
    try {
        const { id, subName } = req.params;

        // $pull removes the specific subName string from the subCommunities array
        const updatedCommunity = await Community.findByIdAndUpdate(
            id,
            { $pull: { subCommunities: subName } },
            { new: true } // Returns the updated document
        );

        if (!updatedCommunity) {
            return res.status(404).json({ success: false, message: "Community not found" });
        }

        res.json({ 
            success: true, 
            message: `Sub-community "${subName}" removed successfully`, 
            data: updatedCommunity 
        });
    } catch (e) {
        console.error("Delete Sub-Community Error:", e);
        res.status(500).json({ success: false, message: "Failed to delete sub-community" });
    }
});
// ====================================================================
// ADMIN: PENDING MASTER DATA APPROVALS
// ====================================================================

// 1. Fetch all pending master data
app.get("/api/admin/pending-data", verifyAdmin, async (req, res) => {
    try {
        const pendingData = await PendingMasterData.find({ status: 'Pending' })
            .populate('submittedBy', 'firstName lastName uniqueId')
            .sort({ createdAt: -1 });
            
        res.json({ success: true, count: pendingData.length, data: pendingData });
    } catch (e) {
        res.status(500).json({ success: false, message: "Server Error" });
    }
});


// ====================================================================
// ADMIN: PENDING MASTER DATA APPROVALS
// ====================================================================

// 2. Approve or Reject Data
app.post("/api/admin/pending-data/action", verifyAdmin, async (req, res) => {
    try {
        const { pendingId, action } = req.body; // action: 'approve' or 'reject'

        const pendingEntry = await PendingMasterData.findById(pendingId);
        if (!pendingEntry) {
            return res.status(404).json({ success: false, message: "Pending entry not found" });
        }

        if (action === 'approve') {
            const { category, value, parentValue } = pendingEntry;

            // --- A. Handle Community ---
            if (category === 'Community') {
                await Community.findOneAndUpdate(
                    { name: new RegExp(`^${value}$`, 'i') },
                    { $setOnInsert: { name: value } }, // Only set if not exists
                    { upsert: true }
                );
            } 
            // --- B. Handle Sub-Community ---
            else if (category === 'SubCommunity') {
                // Ensure the parent community exists, then add the sub-community
                await Community.findOneAndUpdate(
                    { name: new RegExp(`^${parentValue}$`, 'i') },
                    { 
                        $setOnInsert: { name: parentValue }, // Creates parent if missing
                        $addToSet: { subCommunities: value } // Adds sub to array
                    },
                    { upsert: true }
                );
            } 
            // --- C. Handle Standard MasterData (UPDATED FOR HIERARCHY) ---
            else {
                await MasterData.findOneAndUpdate(
                    { 
                        category: category, 
                        name: new RegExp(`^${value}$`, 'i'),
                        parentValue: parentValue || null // Match exactly to the parent
                    },
                    { 
                        $setOnInsert: { 
                            category: category, 
                            name: value,
                            parentValue: parentValue || null // Save the parent link
                        } 
                    },
                    { upsert: true }
                );
            }

            pendingEntry.status = 'Approved';
            await pendingEntry.save();
            return res.json({ success: true, message: "Data approved successfully" });

        } else {
            // --- NEW LOGIC: DELETE IF REJECTED ---
            await PendingMasterData.findByIdAndDelete(pendingId);
            return res.json({ success: true, message: "Data rejected and permanently deleted" });
        }

    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

        
// ====================================================================
// DYNAMIC PAGE CONTENT (Terms, Refund, About)
// ====================================================================

// 1. ADMIN API: Update Page Content (Protected)
app.post("/api/admin/pages", verifyAdmin, async (req, res) => {
    try {
        const { pageName, content } = req.body;

        // UPDATE: Added 'faq' to the validPages array
        const validPages = ['terms', 'refund', 'about', 'faq'];
        if (!validPages.includes(pageName)) {
            return res.status(400).json({ success: false, message: "Invalid page name." });
        }

        if (!content) {
            return res.status(400).json({ success: false, message: "Content cannot be empty." });
        }

        // Use findOneAndUpdate with upsert: true
        // This will UPDATE the document if it exists, or CREATE it if it doesn't.
        const updatedPage = await PageContent.findOneAndUpdate(
            { pageName },
            { 
                content, 
                lastUpdatedBy: req.adminId 
            },
            { new: true, upsert: true }
        );

        res.json({ 
            success: true, 
            message: `${pageName} updated successfully.`, 
            data: updatedPage 
        });

    } catch (error) {
        console.error("Page Update Error:", error);
        res.status(500).json({ success: false, message: "Server Error updating page content." });
    }
});

// 2. PUBLIC API: Get Page Content (Open to everyone)
app.get("/api/pages/:pageName", async (req, res) => {
    try {
        const { pageName } = req.params;

        const page = await PageContent.findOne({ pageName });

        // If the admin hasn't set the content yet, return a graceful fallback
        if (!page) {
            return res.json({ 
                success: true, 
                content: "<p>Content is currently being updated. Please check back later.</p>" 
            });
        }

        res.json({ 
            success: true, 
            content: page.content,
            lastUpdated: page.updatedAt
        });

    } catch (error) {
        console.error("Fetch Page Error:", error);
        res.status(500).json({ success: false, message: "Server Error fetching page content." });
    }
});

// ====================================================================
// TESTIMONIALS (Admin Management & Public View)
// ====================================================================

// 1. ADMIN POST: Create a new Testimonial
app.post("/api/admin/testimonials", verifyAdmin, uploadTestimonial.single("media"), async (req, res) => {
    try {
        // Look for 'videoUrl' in the request body
        const { authorName, content, videoUrl } = req.body;

        if (!authorName || !content) {
            return res.status(400).json({ success: false, message: "Author name and content are required." });
        }

        let mediaUrl = null;
        let mediaType = 'none';

        // 1st Priority: If admin pasted a Video URL
        if (videoUrl && videoUrl.trim() !== '') {
            mediaUrl = videoUrl.trim();
            mediaType = 'video';
        } 
        // 2nd Priority: If admin uploaded an Image file
        else if (req.file) {
            mediaUrl = req.file.path;
            mediaType = 'image';
        }

        const testimonial = new Testimonial({
            authorName,
            content,
            mediaType,
            mediaUrl,
            isApproved: true 
        });

        await testimonial.save();
        res.json({ success: true, message: "Testimonial created successfully", testimonial });

    } catch (error) {
        console.error("Testimonial POST Error:", error);
        res.status(500).json({ success: false, message: "Failed to create testimonial" });
    }
});

// 2. PUBLIC GET: Fetch all approved Testimonials for the frontend
app.get("/api/testimonials", async (req, res) => {
    try {
        const testimonials = await Testimonial.find({ isApproved: true }).sort({ createdAt: -1 });
        res.json({ success: true, count: testimonials.length, data: testimonials });
    } catch (error) {
        console.error("Testimonial GET Error:", error);
        res.status(500).json({ success: false, message: "Failed to fetch testimonials" });
    }
});

// 3. ADMIN DELETE: Remove a Testimonial and clean up Cloudinary
app.delete("/api/admin/testimonials/:id", verifyAdmin, async (req, res) => {
    try {
        const testimonial = await Testimonial.findById(req.params.id);
        if (!testimonial) {
            return res.status(404).json({ success: false, message: "Testimonial not found" });
        }

        // --- CLOUDINARY CLEANUP (ONLY FOR IMAGES NOW) ---
        // If it's a video, it's just a URL string we pasted, so we don't need to ask Cloudinary to delete it here.
        if (testimonial.mediaUrl && testimonial.mediaType === 'image') {
            const parts = testimonial.mediaUrl.split('/');
            const fileWithExt = parts.pop(); 
            const folder = parts.pop(); 
            const publicId = `${folder}/${fileWithExt.split('.')[0]}`; 

            await cloudinary.uploader.destroy(publicId, { resource_type: 'image' });
        }

        await Testimonial.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: "Testimonial deleted successfully" });

    } catch (error) {
        console.error("Testimonial DELETE Error:", error);
        res.status(500).json({ success: false, message: "Failed to delete testimonial" });
    }
});
// ====================================================================
// AGENT FORGOT PASSWORD WORKFLOW
// ====================================================================

// 1. Agent Forgot Password (SEND OTP)
app.post("/api/agent/auth/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;

        // Ensure the email actually belongs to an active Agent
        const agent = await Agent.findOne({ email, isActive: true });
        if (!agent) {
            return res.status(404).json({ success: false, message: "Agent email not found or account inactive" });
        }

        // Generate OTP & Save to MongoDB
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        await Otp.deleteMany({ email }); // Clear old OTPs
        await Otp.create({ email, otp: otpCode });

        const emailContent = generateEmailTemplate(
            "Agent Password Reset OTP",
            `<p>Hello ${agent.name},</p>
             <p>Your OTP for resetting your Agent Dashboard password is:</p>
             <h2 style="letter-spacing: 3px; color:#2c3e50;">${otpCode}</h2>
             <p>This OTP is valid for <strong>5 minutes</strong>.</p>`
        );

        // Send Email using the noreply alias
        await sendMail({ 
            to: email, 
            subject: "Agent Password Reset OTP", 
            html: emailContent,
            fromEmail: `"KalyanaShobha Security" <noreply@kalyanashobha.in>`
        });

        res.json({ success: true, message: "OTP sent to your registered agent email." });

    } catch (err) {
        console.error("Agent Forgot Password Error:", err);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// 2. Agent Verify OTP
app.post("/api/agent/auth/verify-otp", async (req, res) => {
    try {
        const { email, otp } = req.body;

        const otpRecord = await Otp.findOne({ email, otp });

        if (!otpRecord) {
            return res.status(400).json({ success: false, message: "Invalid or Expired OTP" });
        }

        // OTP matched - update the record to mark it as verified
        otpRecord.otp = "VERIFIED";
        await otpRecord.save();

        res.json({ success: true, message: "OTP verified successfully" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// 3. Agent Reset Password
app.post("/api/agent/auth/reset-password", async (req, res) => {
    try {
        const { email, newPassword } = req.body;

        // Check if there is a VERIFIED record in the database
        const verifiedRecord = await Otp.findOne({ email, otp: "VERIFIED" });
        if (!verifiedRecord) {
            return res.status(400).json({ success: false, message: "OTP not verified or session expired" });
        }

        const agent = await Agent.findOne({ email });
        if (!agent) {
            return res.status(404).json({ success: false, message: "Agent not found" });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update the agent's password and save
        agent.password = hashedPassword;
        await agent.save();

        // Delete the used OTP record
        await Otp.deleteOne({ _id: verifiedRecord._id });

        res.json({ success: true, message: "Agent password reset successful!" });

    } catch (err) {
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// ====================================================================
// ADMIN FORGOT PASSWORD WORKFLOW
// ====================================================================

// 1. Admin Forgot Password (SEND OTP)
app.post("/api/admin/auth/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;

        // Ensure the email belongs to an Admin
        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(404).json({ success: false, message: "Admin email not found" });
        }

        // Generate OTP & Save to MongoDB
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        await Otp.deleteMany({ email }); // Clear old OTPs
        await Otp.create({ email, otp: otpCode });

        const emailContent = generateEmailTemplate(
            "Admin Password Reset Verification",
            `<p>Hello ${admin.username},</p>
             <p>A request was made to reset your Admin Dashboard password. Your verification code is:</p>
             <h2 style="letter-spacing: 3px; color:#c0392b;">${otpCode}</h2>
             <p>This code is valid for <strong>5 minutes</strong>. If you did not request this, please ignore this email.</p>`
        );

        // Send Email using the noreply alias
        await sendMail({ 
            to: email, 
            subject: "Admin Password Reset OTP", 
            html: emailContent,
            fromEmail: `"KalyanaShobha Security" <noreply@kalyanashobha.in>`
        });

        res.json({ success: true, message: "OTP sent to registered admin email." });

    } catch (err) {
        console.error("Admin Forgot Password Error:", err);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// 2. Admin Verify OTP
app.post("/api/admin/auth/verify-otp", async (req, res) => {
    try {
        const { email, otp } = req.body;

        const otpRecord = await Otp.findOne({ email, otp });

        if (!otpRecord) {
            return res.status(400).json({ success: false, message: "Invalid or Expired OTP" });
        }

        // OTP matched - update the record to mark it as verified
        otpRecord.otp = "VERIFIED";
        await otpRecord.save();

        res.json({ success: true, message: "OTP verified successfully" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// 3. Admin Reset Password
app.post("/api/admin/auth/reset-password", async (req, res) => {
    try {
        const { email, newPassword } = req.body;

        // Check if there is a VERIFIED record in the database
        const verifiedRecord = await Otp.findOne({ email, otp: "VERIFIED" });
        if (!verifiedRecord) {
            return res.status(400).json({ success: false, message: "OTP not verified or session expired" });
        }

        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(404).json({ success: false, message: "Admin not found" });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update the admin's password and save
        admin.password = hashedPassword;
        await admin.save();

        // Delete the used OTP record to prevent reuse
        await Otp.deleteOne({ _id: verifiedRecord._id });

        res.json({ success: true, message: "Admin password reset successful!" });

    } catch (err) {
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// ====================================================================
// 1. REORDER MASTER DATA (Independent Items)
// ====================================================================
app.post("/api/admin/master-data/reorder", verifyAdmin, async (req, res) => {
    try {
        const { orderedItems } = req.body; 
        // Expected frontend payload: [{ _id: "123", order: 1 }, { _id: "456", order: 2 }]

        if (!orderedItems || !Array.isArray(orderedItems)) {
            return res.status(400).json({ success: false, message: "Invalid data format" });
        }

        const bulkOps = orderedItems.map(item => ({
            updateOne: {
                filter: { _id: item._id },
                update: { order: item.order }
            }
        }));

        await MasterData.bulkWrite(bulkOps);
        res.json({ success: true, message: "Master data order updated successfully" });

    } catch (e) {
        console.error("Master Data Reorder Error:", e);
        res.status(500).json({ success: false, message: e.message });
    }
});

// ====================================================================
// 2. REORDER MAIN COMMUNITIES
// ====================================================================
app.post("/api/admin/community/reorder", verifyAdmin, async (req, res) => {
    try {
        const { orderedItems } = req.body;

        if (!orderedItems || !Array.isArray(orderedItems)) {
            return res.status(400).json({ success: false, message: "Invalid data format" });
        }

        const bulkOps = orderedItems.map(item => ({
            updateOne: {
                filter: { _id: item._id },
                update: { order: item.order }
            }
        }));

        await Community.bulkWrite(bulkOps);
        res.json({ success: true, message: "Community order updated successfully" });

    } catch (e) {
        console.error("Community Reorder Error:", e);
        res.status(500).json({ success: false, message: e.message });
    }
});

// ====================================================================
// 3. REORDER SUB-COMMUNITIES (Inside a specific Community)
// ====================================================================
app.post("/api/admin/community/:id/reorder-sub", verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { orderedSubCommunities } = req.body; 
        // Expected payload: ["Yadav", "Brahmin", "Reddy"] (Strings in the new dragged order)

        if (!orderedSubCommunities || !Array.isArray(orderedSubCommunities)) {
            return res.status(400).json({ success: false, message: "Invalid array format" });
        }

        // Just overwrite the array. MongoDB keeps arrays in the exact order you save them!
        const community = await Community.findByIdAndUpdate(
            id,
            { subCommunities: orderedSubCommunities },
            { new: true }
        );

        if (!community) {
            return res.status(404).json({ success: false, message: "Community not found" });
        }

        res.json({ success: true, message: "Sub-community order updated", data: community });

    } catch (e) {
        console.error("Sub-Community Reorder Error:", e);
        res.status(500).json({ success: false, message: e.message });
    }
});

// Create a new Sub Admin / Moderator
app.post("/api/admin/create-moderator", verifyAdmin, async (req, res) => {
    try {
        const { username, email, password, permissions } = req.body;

        // Check if the current user creating this is a SuperAdmin
        const creator = await Admin.findById(req.adminId);
        if (creator.role !== 'SuperAdmin') {
            return res.status(403).json({ success: false, message: "Only SuperAdmin can create Moderators" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newModerator = new Admin({
            username,
            email,
            password: hashedPassword,
            role: 'Moderator',
            permissions: permissions // e.g., ["users", "vendors", "vendor-leads"]
        });

        await newModerator.save();

        // --- NEW: SEND WELCOME EMAIL TO MODERATOR ---
        const moderatorEmailContent = generateEmailTemplate(
            "Welcome to KalyanaShobha Admin Portal",
            `<p>Dear ${username},</p>
             <p>Your moderator account has been successfully created by the Super Admin.</p>
             <p>Here are your official login credentials:</p>
             <table style="width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; background: #fafafa; border: 1px solid #eeeeee;">
                <tr>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; width: 40%; color: #555;"><strong>Login URL:</strong></td>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee;"><a href="https://kalyanashobha.in/admin" style="color: #D32F2F; text-decoration: none; font-weight: bold;">kalyanashobha.in/admin</a></td>
                </tr>
                <tr>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #555;"><strong>Email ID:</strong></td>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #222; font-weight: bold;">${email}</td>
                </tr>
                <tr>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #555;"><strong>Password:</strong></td>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #222; font-weight: bold;">${password}</td>
                </tr>
                <tr>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #555;"><strong>Permissions:</strong></td>
                    <td style="padding: 12px; border-bottom: 1px solid #eeeeee; color: #222; font-weight: bold;">${permissions ? permissions.join(', ') : 'None assigned yet'}</td>
                </tr>
             </table>
             <p style="margin-top: 20px;">Please keep these credentials safe and do not share them with anyone. We recommend changing your password after your first login.</p>
             <div style="margin-top: 30px; text-align: center;">
                <a href="https://kalyanashobha.in/admin" style="background-color: #D32F2F; color: white; padding: 12px 25px; text-decoration: none; border-radius: 4px; font-size: 14px; font-weight: bold; display: inline-block;">Login to Dashboard</a>
             </div>`
        );

        // Send the email but don't stop the request if it fails
        try {
            await sendMail({ 
                to: email, 
                subject: "Your Moderator Portal Login Credentials", 
                html: moderatorEmailContent 
            });
            console.log("Moderator welcome email sent.");
        } catch (mailErr) {
            console.error("Failed to send moderator email:", mailErr);
        }

        res.json({ success: true, message: "Moderator created and email sent successfully" });

    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});


// ====================================================================
// ADMIN: EDIT USER PROFILE & PHOTOS (NOW WITH MASTER DATA STAGING)
// ====================================================================
app.put("/api/admin/users/:id/update", verifyAdmin, uploadProfile.array("newPhotos", 5), async (req, res) => {
    try {
        const userId = req.params.id;
        const { 
            firstName, lastName, gender, dob, maritalStatus, height, diet,
            community, subCommunity, gothra, highestQualification, collegeName,
            jobRole, companyName, annualIncome, city, state, country, residentsIn,
            existingPhotos, 
            astrologyDetails, 
            familyDetails     
        } = req.body;

        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        // 1. Handle Existing Photos
        let updatedPhotos = [];
        if (existingPhotos) {
            updatedPhotos = Array.isArray(existingPhotos) ? existingPhotos : [existingPhotos];
        }

        // 2. Delete discarded photos from Cloudinary
        const photosToDelete = (user.photos || []).filter(photo => !updatedPhotos.includes(photo));
        if (photosToDelete.length > 0) {
            const deletePromises = photosToDelete.map(imageUrl => {
                const parts = imageUrl.split('/');
                const fileWithExt = parts.pop();
                const folder = parts.pop();
                const publicId = `${folder}/${fileWithExt.split('.')[0]}`;
                return cloudinary.uploader.destroy(publicId);
            });
            await Promise.all(deletePromises);
        }

        // 3. Add Newly Uploaded Photos
        if (req.files && req.files.length > 0) {
            const newPhotoUrls = req.files.map(f => f.path);
            updatedPhotos = [...updatedPhotos, ...newPhotoUrls];
        }

        // Cap at 2 photos
        if (updatedPhotos.length > 2) updatedPhotos = updatedPhotos.slice(0, 2);

        // 4. Parse the newly added JSON strings sent from Frontend
        const parsedAstrology = astrologyDetails ? JSON.parse(astrologyDetails) : {};
        const parsedFamily = familyDetails ? JSON.parse(familyDetails) : {};

        // 5. Update Database
        const updatedUser = await User.findByIdAndUpdate(
            userId, 
            { $set: {
                firstName, lastName, gender, dob, maritalStatus, height, diet,
                community, subCommunity, gothra, highestQualification, collegeName,
                jobRole, companyName, annualIncome, city, state, country, residentsIn,
                photos: updatedPhotos,
                astrologyDetails: parsedAstrology, 
                familyDetails: parsedFamily        
            }},
            { new: true } 
        ).select("-password");

        // --- NEW: THE MAGIC STAGING LOGIC FOR ADMIN EDITS ---
        // This will check if the Admin typed a new city, gothra, education, etc. 
        // and push it to the Pending Master Data table for approval!
        await checkAndStageNewMasterData(userId, req.body);
        await checkAndStageExtraMasterData(userId, parsedAstrology);
        // ------------------------------------------------------

        res.json({ success: true, message: "Profile updated successfully", user: updatedUser });

    } catch (e) {
        console.error("Admin Profile Update Error:", e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});
                

// ====================================================================
// USER PREFERENCES (GET & POST)
// ====================================================================

// GET: Fetch User Preferences
app.get("/api/user/preference", verifyUser, async (req, res) => {
    try {
        const preference = await Preference.findOne({ userId: req.userId });
        res.json({ success: true, data: preference });
    } catch (e) {
        console.error("Fetch Preference Error:", e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// POST: Save or Update User Preferences
app.post("/api/user/preference", verifyUser, async (req, res) => {
    try {
        // We use findOneAndUpdate with upsert: true
        // If a preference exists, it updates it. If not, it creates a new one.
        const updatedPref = await Preference.findOneAndUpdate(
            { userId: req.userId },
            { $set: { ...req.body, userId: req.userId } },
            { new: true, upsert: true }
        );
        res.json({ success: true, message: "Partner preferences saved successfully!", data: updatedPref });
    } catch (e) {
        console.error("Save Preference Error:", e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});



// ====================================================================
// ADMIN: SETTINGS & FEES
// ====================================================================

// GET: Fetch current fee settings
app.get("/api/admin/settings/fees", verifyAdmin, async (req, res) => {
    try {
        let settings = await Settings.findOne();
        
        // If no settings exist yet, return defaults
        if (!settings) {
            settings = { maleRegistrationFee: 0, femaleRegistrationFee: 0 };
        }
        
        res.json({ success: true, data: settings });
    } catch (error) {
        console.error("Fetch Settings Error:", error);
        res.status(500).json({ success: false, message: "Server Error fetching settings" });
    }
});

// POST: Update fee settings
app.post("/api/admin/settings/fees", verifyAdmin, async (req, res) => {
    try {
        const { maleFee, femaleFee } = req.body;

        if (maleFee === undefined || femaleFee === undefined) {
            return res.status(400).json({ success: false, message: "Both male and female fees are required." });
        }

        // findOneAndUpdate with upsert ensures we only ever have ONE settings document
        const updatedSettings = await Settings.findOneAndUpdate(
            {}, // Empty filter targets the first document it finds
            { 
                $set: { 
                    maleRegistrationFee: maleFee, 
                    femaleRegistrationFee: femaleFee,
                    lastUpdatedBy: req.adminId
                } 
            },
            { new: true, upsert: true }
        );

        res.json({ success: true, message: "Fees updated successfully", data: updatedSettings });
    } catch (error) {
        console.error("Update Settings Error:", error);
        res.status(500).json({ success: false, message: "Server Error updating settings" });
    }
});
// ====================================================================
// USER: Get Registration Fee & Dynamic UPI ID
// ====================================================================

app.get("/api/user/registration-fee", verifyUser, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('gender isPaidMember');
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        const settings = await Settings.findOne();

        // Determine the fee based on the user's gender (safely checking if settings exist)
        const requiredFee = user.gender === 'Male' 
            ? (settings?.maleRegistrationFee || 0) 
            : (settings?.femaleRegistrationFee || 0);

        // Get the dynamic UPI ID. If the admin hasn't set one yet, it will say "Not Set"
        const finalUpiId = (settings && settings.upiId) ? settings.upiId : "Not Set";

        res.json({ 
            success: true, 
            fee: requiredFee, 
            gender: user.gender,
            isAlreadyPaid: user.isPaidMember,
            upiId: finalUpiId // <-- Sends exactly what is in the database
        });

    } catch (error) {
        console.error("User Fee Fetch Error:", error);
        res.status(500).json({ success: false, message: "Server Error fetching fee" });
    }
});


// ====================================================================
// NEW: PREMIUM MEMBERSHIP REQUEST LOGIC
// ====================================================================

// 1. GET: Check if the user has already requested premium
app.get("/api/user/premium-status", verifyUser, async (req, res) => {
    try {
        // Fetch the most recent request for this user
        const existingRequest = await PremiumRequest.findOne({ userId: req.userId }).sort({ requestDate: -1 });

        if (existingRequest) {
            res.json({ success: true, hasRequested: true, status: existingRequest.status });
        } else {
            res.json({ success: true, hasRequested: false, status: null });
        }
    } catch (error) {
        console.error("Premium Status Error:", error);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});


// 2. POST: Submit a new premium request
app.post("/api/user/premium-click-alert", verifyUser, async (req, res) => {
    try {
        // Check if a request already exists
        const existingRequest = await PremiumRequest.findOne({ 
            userId: req.userId, 
            status: { $in: ['Pending', 'Contacted'] } 
        });

        if (existingRequest) {
            return res.json({ success: true, message: "You have already requested an upgrade. Our team will contact you shortly." });
        }

        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        // Save the request to the database
        const newRequest = new PremiumRequest({ userId: req.userId });
        await newRequest.save();

        // Prepare Email Content for Admin
        const adminAlertContent = generateEmailTemplate(
            "Premium Membership Request",
            `<p>A user has requested an upgrade to Premium Membership.</p>
             <table style="width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px;">
                <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; width: 40%; color: #666;"><strong>Name:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${user.firstName} ${user.lastName}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Profile ID:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>${user.uniqueId}</strong></td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Email:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${user.email}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Mobile:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${user.mobileNumber}</td></tr>
             </table>
             <div style="margin-top: 20px; text-align: center;">
                <a href="https://kalyanashobha.in/admin" style="background-color: #2c3e50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; font-size: 14px;">Go to Admin Dashboard</a>
             </div>`
        );

        // Send Email to Admin
        await sendMail({ 
            to: EMAIL_USER,
            subject: `Premium Request: ${user.firstName} (${user.uniqueId})`, 
            html: adminAlertContent 
        });

        res.json({ success: true, message: "Request sent successfully! Our team will contact you shortly." });

    } catch (error) {
        console.error("Premium Request Error:", error);
        res.status(500).json({ success: false, message: "Server Error notifying admin" });
    }
});

// ====================================================================
// ADMIN: MANAGE PREMIUM REQUESTS
// ====================================================================

// 1. Fetch all premium requests
app.get("/api/admin/premium-requests", verifyAdmin, async (req, res) => {
    try {
        const requests = await PremiumRequest.find()
            .populate('userId', 'firstName lastName uniqueId email mobileNumber gender city state')
            .sort({ requestDate: -1 }); // Newest first

        res.json({ success: true, count: requests.length, data: requests });
    } catch (error) {
        console.error("Fetch Premium Requests Error:", error);
        res.status(500).json({ success: false, message: "Server Error fetching requests" });
    }
});

// 2. Update status of a request
app.put("/api/admin/premium-requests/:id/status", verifyAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        const validStatuses = ['Pending', 'Contacted', 'Resolved'];
        
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ success: false, message: "Invalid status" });
        }

        const request = await PremiumRequest.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true }
        );

        if (!request) {
            return res.status(404).json({ success: false, message: "Request not found" });
        }

        res.json({ success: true, message: `Status updated to ${status}`, data: request });
    } catch (error) {
        console.error("Update Premium Request Error:", error);
        res.status(500).json({ success: false, message: "Server Error updating status" });
    }
});

// ====================================================================
// POST-LOGIN: ACCEPT TERMS & UPLOAD SIGNATURE (For Agent Referrals)
// ====================================================================
app.post("/api/user/accept-terms", verifyUser, uploadSignature.single('digitalSignature'), async (req, res) => {
    try {
        // 1. Ensure the file was uploaded
        if (!req.file) {
            return res.status(400).json({ 
                success: false, 
                message: "Digital Signature file is required." 
            });
        }

        // 2. Capture IP Address for legal compliance
        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        // 3. Update the User document
        const updatedUser = await User.findByIdAndUpdate(
            req.userId,
            {
                $set: {
                    digitalSignature: req.file.path,
                    termsAcceptedAt: new Date(),
                    termsAcceptedIP: clientIp
                }
            },
            { new: true }
        ).select("-password -otp");

        if (!updatedUser) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        res.json({ 
            success: true, 
            message: "Terms accepted and signature saved successfully.", 
            user: updatedUser 
        });

    } catch (e) {
        console.error("Accept Terms Error:", e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// Admin: Get all vendor leads
app.get("/api/admin/vendor-leads", verifyAdmin, async (req, res) => {
    try {
        // Fetch leads and populate the vendor details
        const leads = await VendorLead.find()
            .populate('vendorId', 'vendorId businessName category contactNumber') 
            .sort({ createdAt: -1 }); // Newest leads first

        res.json({ 
            success: true, 
            count: leads.length, 
            data: leads 
        });

    } catch (error) {
        console.error("Fetch Admin Leads Error:", error);
        res.status(500).json({ success: false, message: "Server Error fetching vendor leads" });
    }
});
// Get all Moderators
app.get("/api/admin/moderators", verifyAdmin, async (req, res) => {
    try {
        // Security Check: Only SuperAdmin can view the moderator list
        const caller = await Admin.findById(req.adminId);
        if (caller.role !== 'SuperAdmin') {
            return res.status(403).json({ success: false, message: "Access Denied: Only SuperAdmins can view moderators" });
        }

        const moderators = await Admin.find({ role: 'Moderator' })
            .select('-password') // Hide passwords
            .sort({ createdAt: -1 });

        res.json({ success: true, count: moderators.length, data: moderators });

    } catch (e) {
        console.error("Fetch Moderators Error:", e);
        res.status(500).json({ success: false, message: "Server Error fetching moderators" });
    }
});

// Edit a Moderator
app.put("/api/admin/moderators/:id", verifyAdmin, async (req, res) => {
    try {
        // Security Check: Only SuperAdmin can edit moderators
        const caller = await Admin.findById(req.adminId);
        if (caller.role !== 'SuperAdmin') {
            return res.status(403).json({ success: false, message: "Access Denied: Only SuperAdmins can edit moderators" });
        }

        const { username, email, permissions, password } = req.body;
        const updateData = { username, email, permissions };

        // If a new password was provided in the edit form, hash it
        if (password && password.trim() !== "") {
            const salt = await bcrypt.genSalt(10);
            updateData.password = await bcrypt.hash(password, salt);
        }

        const updatedModerator = await Admin.findByIdAndUpdate(
            req.params.id,
            { $set: updateData },
            { new: true } // Return the updated document
        ).select('-password');

        if (!updatedModerator) {
            return res.status(404).json({ success: false, message: "Moderator not found" });
        }

        res.json({ success: true, message: "Moderator updated successfully", data: updatedModerator });

    } catch (e) {
        console.error("Edit Moderator Error:", e);
        res.status(500).json({ success: false, message: e.message });
    }
});


   // Delete a Moderator
app.delete("/api/admin/moderators/:id", verifyAdmin, async (req, res) => {
    try {
        // Security Check: Only SuperAdmin can delete moderators
        const caller = await Admin.findById(req.adminId);
        if (caller.role !== 'SuperAdmin') {
            return res.status(403).json({ success: false, message: "Access Denied: Only SuperAdmins can delete moderators" });
        }

        const deletedModerator = await Admin.findByIdAndDelete(req.params.id);

        if (!deletedModerator) {
            return res.status(404).json({ success: false, message: "Moderator not found" });
        }

        res.json({ success: true, message: "Moderator deleted successfully" });

    } catch (e) {
        console.error("Delete Moderator Error:", e);
        res.status(500).json({ success: false, message: "Server Error deleting moderator" });
    }
});

// ====================================================================
// VENDOR SELF-REGISTRATION (PUBLIC)
// ====================================================================

// Vendor submits their details for approval
app.post("/api/vendor/register", uploadVendor.array("images", 5), async (req, res) => {
    try {
        const { businessName, email, category, description, contactNumber, priceRange } = req.body;

        if (!businessName || !email || !category || !contactNumber) {
            return res.status(400).json({ success: false, message: "Business Name, Email, Category, and Contact Number are required." });
        }

        // Check if a vendor with this email already exists
        const existingVendor = await Vendor.findOne({ email });
        if (existingVendor) {
            return res.status(400).json({ success: false, message: "A vendor with this email already exists." });
        }

        const images = req.files && req.files.length > 0 ? req.files.map(file => file.path) : [];
        const vendorId = await generateVendorId();

        const vendor = new Vendor({
            vendorId,
            businessName,
            email,
            category,
            description,
            contactNumber,
            priceRange,
            images,
            isApproved: false // Explicitly false so admin has to review
        });

        await vendor.save();

        // Email to the Vendor
        const vendorEmailContent = generateEmailTemplate(
            "Registration Received",
            `<p>Dear ${businessName} Team,</p>
             <p>Thank you for registering on KalyanaShobha. We have received your details.</p>
             <p>Our admin team is currently reviewing your application. You will be notified once your profile is approved and live on our platform.</p>`
        );

        // Email Alert to Admin
        const adminAlertContent = generateEmailTemplate(
            "New Vendor Registration Request",
            `<p>A new vendor has submitted a registration request.</p>
             <table style="width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px;">
                <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; width: 40%; color: #666;"><strong>Business Name:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${businessName}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Category:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${category}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #ddd; color: #666;"><strong>Contact:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${contactNumber} / ${email}</td></tr>
             </table>
             <div style="margin-top: 20px; text-align: center;">
                <a href="https://kalyanashobha.in/admin" style="background-color: #D32F2F; color: white; padding: 12px 25px; text-decoration: none; border-radius: 4px; font-weight: bold;">Review in Dashboard</a>
             </div>`
        );

        // Send Emails asynchronously
        sendMail({ to: email, subject: "Vendor Registration Received", html: vendorEmailContent }).catch(e => console.error(e));
        sendMail({ to: EMAIL_USER, subject: `New Vendor Request: ${businessName}`, html: adminAlertContent }).catch(e => console.error(e));

        res.json({ success: true, message: "Registration submitted successfully. Pending admin approval." });

    } catch (error) {
        console.error("Vendor Registration Error:", error);
        res.status(500).json({ success: false, message: "Server Error during registration" });
    }
});


// ====================================================================
// ADMIN VENDOR APPROVAL WORKFLOW
// ====================================================================

// 1. GET: Fetch only pending vendor requests
app.get("/api/admin/vendor-requests", verifyAdmin, async (req, res) => {
    try {
        const pendingVendors = await Vendor.find({ isApproved: false }).sort({ createdAt: -1 });
        res.json({ success: true, count: pendingVendors.length, vendors: pendingVendors });
    } catch (error) {
        console.error("Fetch Pending Vendors Error:", error);
        res.status(500).json({ success: false, message: "Failed to fetch vendor requests" });
    }
});

// 2. POST: Approve or Reject a vendor
app.post("/api/admin/vendors/action", verifyAdmin, async (req, res) => {
    try {
        const { vendorObjectId, action, rejectionReason } = req.body; // action should be 'approve' or 'reject'

        const vendor = await Vendor.findById(vendorObjectId);
        if (!vendor) return res.status(404).json({ success: false, message: "Vendor not found" });

        if (action === 'approve') {
            vendor.isApproved = true;
            await vendor.save();

            const approvalEmail = generateEmailTemplate(
                "Vendor Profile Approved!",
                `<p>Dear ${vendor.businessName} Team,</p>
                 <p>Congratulations! Your vendor profile has been approved and is now visible to thousands of users on KalyanaShobha.</p>
                 <p>Users can now view your details and contact you for business inquiries.</p>`
            );

            await sendMail({ to: vendor.email, subject: "Your KalyanaShobha Vendor Profile is Live!", html: approvalEmail });
            return res.json({ success: true, message: "Vendor approved successfully." });

        } else if (action === 'reject') {
            // CLOUDINARY CLEANUP: If rejected, we must delete their images to save space
            if (vendor.images && vendor.images.length > 0) {
                const deletePromises = vendor.images.map(imageUrl => {
                    const parts = imageUrl.split('/');
                    const fileWithExt = parts.pop(); 
                    const folder = parts.pop(); 
                    const publicId = `${folder}/${fileWithExt.split('.')[0]}`; 
                    return cloudinary.uploader.destroy(publicId);
                });
                await Promise.all(deletePromises);
            }

            // Delete the vendor from DB entirely
            await Vendor.findByIdAndDelete(vendorObjectId);

            const rejectionEmail = generateEmailTemplate(
                "Vendor Registration Update",
                `<p>Dear ${vendor.businessName} Team,</p>
                 <p>We have reviewed your registration request for KalyanaShobha.</p>
                 <p>Unfortunately, we are unable to approve your profile at this time.</p>
                 ${rejectionReason ? `<p><strong>Reason:</strong> ${rejectionReason}</p>` : ""}
                 <p>If you believe this is a mistake, please reach out to our support team.</p>`
            );

            await sendMail({ to: vendor.email, subject: "KalyanaShobha Registration Update", html: rejectionEmail });
            return res.json({ success: true, message: "Vendor rejected and deleted successfully." });

        } else {
            return res.status(400).json({ success: false, message: "Invalid action. Use 'approve' or 'reject'." });
        }

    } catch (error) {
        console.error("Vendor Action Error:", error);
        res.status(500).json({ success: false, message: "Server Error processing vendor action" });
    }
});


// ====================================================================
// ADMIN: Update Global Settings (Fees & UPI ID)
// ====================================================================
app.put("/api/admin/settings", verifyAdmin, async (req, res) => {
    try {
        const { maleRegistrationFee, femaleRegistrationFee, upiId } = req.body;

        // Fetch the first settings document or create one if it doesn't exist
        let settings = await Settings.findOne();
        if (!settings) {
            settings = new Settings({});
        }

        if (maleRegistrationFee !== undefined) settings.maleRegistrationFee = maleRegistrationFee;
        if (femaleRegistrationFee !== undefined) settings.femaleRegistrationFee = femaleRegistrationFee;
        if (upiId !== undefined) settings.upiId = upiId;

        settings.lastUpdatedBy = req.adminId; // Tracks which admin made the change
        await settings.save();

        res.json({ success: true, message: "Settings updated successfully", settings });
    } catch (error) {
        console.error("Update Settings Error:", error);
        res.status(500).json({ success: false, message: "Server Error updating settings" });
    }
});


// ====================================================================
// USER: Get Registration Fee & Dynamic UPI ID
// ====================================================================
app.get("/api/user/registration-fee", verifyUser, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        // Fetch settings, fallback to defaults if not found
        const settings = await Settings.findOne() || { 
            maleRegistrationFee: 0, 
            femaleRegistrationFee: 0, 
            upiId: '8897714968@axl' 
        };

        // Determine fee based on user gender
        const fee = user.gender === 'Female' ? settings.femaleRegistrationFee : settings.maleRegistrationFee;

        res.json({
            success: true,
            fee: fee,
            upiId: settings.upiId // Send the dynamic UPI ID to the frontend
        });
    } catch (error) {
        console.error("Fetch Fee Error:", error);
        res.status(500).json({ success: false, message: "Server Error fetching fee" });
    }
});

// ====================================================================
// ADMIN: FETCH RESOLVED PREMIUM REQUESTS
// ====================================================================

app.get("/api/admin/premium-requests/resolved", verifyAdmin, async (req, res) => {
    try {
        // Query only for requests where the status is 'Resolved'
        const resolvedRequests = await PremiumRequest.find({ status: 'Resolved' })
            .populate('userId', 'firstName lastName uniqueId email mobileNumber gender city state')
            .sort({ requestDate: -1 }); // Newest resolved requests first

        res.json({ 
            success: true, 
            count: resolvedRequests.length, 
            data: resolvedRequests 
        });
        
    } catch (error) {
        console.error("Fetch Resolved Premium Requests Error:", error);
        res.status(500).json({ success: false, message: "Server Error fetching resolved requests" });
    }
});

// ====================================================================
// AGENT: FETCH OWN RESOLVED PREMIUM USERS
// ====================================================================

app.get("/api/agent/premium-requests/resolved", verifyAgent, async (req, res) => {
    try {
        // 1. Get IDs of all users referred by this specific agent
        const myUsers = await User.find({ referredByAgentId: req.agentId }).select('_id');
        const userIds = myUsers.map(u => u._id);

        if (userIds.length === 0) {
            return res.json({ success: true, count: 0, data: [] });
        }

        // 2. Find Premium Requests for these users where status is 'Resolved'
        const resolvedPremiumUsers = await PremiumRequest.find({
            status: 'Resolved',
            userId: { $in: userIds }
        })
        .populate('userId', 'firstName lastName uniqueId mobileNumber email gender city state')
        .sort({ requestDate: -1 });

        res.json({ 
            success: true, 
            count: resolvedPremiumUsers.length, 
            data: resolvedPremiumUsers 
        });

    } catch (error) {
        console.error("Agent Resolved Premium Users Error:", error);
        res.status(500).json({ success: false, message: "Server Error fetching resolved premium users" });
    }
});

// ====================================================================
// ADMIN: FETCH RESOLVED PREMIUM USERS FOR A SPECIFIC AGENT
// ====================================================================

app.get("/api/admin/agents/:agentId/premium-resolved", verifyAdmin, async (req, res) => {
    try {
        const { agentId } = req.params;

        // 1. Get IDs of all users referred by the targeted agent
        const agentUsers = await User.find({ referredByAgentId: agentId }).select('_id');
        const userIds = agentUsers.map(u => u._id);

        if (userIds.length === 0) {
            return res.json({ success: true, count: 0, data: [] });
        }

        // 2. Find Premium Requests for these users where status is 'Resolved'
        const resolvedRequests = await PremiumRequest.find({
            status: 'Resolved',
            userId: { $in: userIds }
        })
        .populate('userId', 'firstName lastName uniqueId email mobileNumber gender city state')
        .sort({ requestDate: -1 });

        res.json({ 
            success: true, 
            count: resolvedRequests.length, 
            data: resolvedRequests 
        });

    } catch (error) {
        console.error("Admin Fetch Agent Premium Resolved Error:", error);
        res.status(500).json({ success: false, message: "Server Error fetching agent's premium users" });
    }
});

// ====================================================================
// ADMIN: FETCH ALL USERS FOR A SPECIFIC AGENT
// ====================================================================

app.get("/api/admin/agents/:agentId/users", verifyAdmin, async (req, res) => {
    try {
        const { agentId } = req.params;

        // 1. Verify if the agent exists (optional but recommended for clean error handling)
        const agent = await Agent.findById(agentId).select('name agentCode');
        if (!agent) {
            return res.status(404).json({ success: false, message: "Agent not found" });
        }

        // 2. Fetch all users where referredByAgentId matches the requested agent
        const agentUsers = await User.find({ referredByAgentId: agentId })
            .select('-password -fcmToken -digitalSignature') // Exclude heavy/sensitive fields to optimize performance
            .sort({ createdAt: -1 }); // Newest registrations first

        res.json({ 
            success: true, 
            count: agentUsers.length,
            agentName: agent.name,
            agentCode: agent.agentCode,
            data: agentUsers 
        });

    } catch (error) {
        console.error("Admin Fetch Agent Users Error:", error);
        res.status(500).json({ success: false, message: "Server Error fetching agent's users" });
    }
});


                                                  
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
