
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

// ---------------- MODELS ----------------
const User = require('./models/User');
const Agent = require('./models/Agent');
const Vendor = require('./models/Vendor');
const Interest = require('./models/Interest');
const PaymentRegistration = require('./models/PaymentRegistration');
const PaymentInterest = require('./models/PaymentInterest');
const Admin = require('./models/Admin');

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
            dbName: "kalyanashobha", // Optional: explicit DB name
            serverSelectionTimeoutMS: 5000, // Timeout after 5s if DB is unreachable
            socketTimeoutMS: 45000, // Close sockets after 45s
        });
        isConnected = true;
        console.log("MongoDB Connected (New Connection)");
    } catch (error) {
        console.error("MongoDB Connection Failed:", error);
        // We do NOT exit the process here, so the server stays alive for retry
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
const profileStorage = new CloudinaryStorage({
    cloudinary,
    params: { folder: "matrimony_users", allowed_formats: ["jpg", "jpeg", "png"], transformation: [{ width: 800, height: 800, crop: "limit" }] }
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


// ---------------- EMAIL SYSTEM (PROFESSIONAL) ----------------
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "adepusanjay444@gmail.com",
    pass: "lrnesuqvssiognej"   // Gmail App Password
  }
});

// Professional HTML Template Generator
const generateEmailTemplate = (title, bodyContent) => {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }
            .container { max-width: 600px; margin: 20px auto; background-color: #ffffff; border: 1px solid #dddddd; }
            .header { background-color: #2c3e50; color: #ffffff; padding: 20px; text-align: center; }
            .header h1 { margin: 0; font-size: 24px; letter-spacing: 1px; }
            .content { padding: 30px; color: #333333; line-height: 1.6; }
            .footer { background-color: #f4f4f4; color: #777777; padding: 15px; text-align: center; font-size: 12px; border-top: 1px solid #dddddd; }
            .button { display: inline-block; padding: 10px 20px; background-color: #2c3e50; color: #ffffff; text-decoration: none; border-radius: 4px; margin-top: 15px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>KalyanaShobha</h1>
            </div>
            <div class="content">
                <h2 style="color: #2c3e50; font-size: 20px; border-bottom: 2px solid #eee; padding-bottom: 10px;">${title}</h2>
                ${bodyContent}
                <p style="margin-top: 30px;">Sincerely,<br>The KalyanaShobha Team</p>
            </div>
            <div class="footer">
                <p>This is an automated message. Please do not reply directly to this email.</p>
                <p>&copy; ${new Date().getFullYear()} KalyanaShobha Matrimony. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    `;
};

async function sendMail({ to, subject, html }) {
    try {
        await transporter.sendMail({
            from: `"KalyanaShobha Notifications" <${process.env.EMAIL_USER}>`,
            to, 
            subject,
            html // The HTML is already formatted by generateEmailTemplate before being passed here
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

// 1. Agent Login Init (Password Check -> Send OTP)
app.post("/api/agent/auth/login-init", async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Find Agent
        const agent = await Agent.findOne({ email, isActive: true });
        if (!agent) return res.status(404).json({ success: false, message: "Agent not found or inactive" });

        // 2. Validate Password
        const isMatch = await bcrypt.compare(password, agent.password);
        if (!isMatch) return res.status(400).json({ success: false, message: "Invalid credentials" });

        // 3. Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = otp; // Reusing your existing otpStore object
        setTimeout(() => delete otpStore[email], 300000); // 5 mins expiry

        // 4. Send Email
        const emailContent = generateEmailTemplate(
            "Agent Dashboard Access",
            `<p>Hello ${agent.name},</p>
             <p>Your OTP for Agent Dashboard login is:</p>
             <h2 style="color: #2c3e50; letter-spacing: 5px;">${otp}</h2>`
        );
        await sendMail({ to: email, subject: "Agent Login OTP", html: emailContent });

        res.json({ success: true, message: "OTP sent to email" });

    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// 2. Agent Login Verify (Verify OTP -> Return Token & Details)
app.post("/api/agent/auth/login-verify", async (req, res) => {
    try {
        const { email, otp } = req.body;

        if (otpStore[email] && parseInt(otpStore[email]) === parseInt(otp)) {
            const agent = await Agent.findOne({ email });
            delete otpStore[email];

            const token = jwt.sign(
                { id: agent._id, role: 'Agent' }, 
                process.env.JWT_SECRET || "fallback_secret_key", 
                { expiresIn: "1d" }
            );

            // Return Agent Info (Include ID and Name for the Referral Link logic)
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
        
        // 1. Check Admin existence
        const admin = await Admin.findOne({ email });
        if (!admin) return res.status(404).json({ success: false, message: "Admin not found" });

        // 2. Check Password
        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) return res.status(400).json({ success: false, message: "Invalid credentials" });

        // 3. Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = otp;

        // Auto-expire OTP after 5 minutes
        setTimeout(() => delete otpStore[email], 300000); 

        // 4. Send Email
        const emailContent = generateEmailTemplate(
            "Admin Dashboard Access",
            `<p>A login attempt was made for the Admin Panel.</p>
             <p>Your Verification Code is:</p>
             <h2 style="color: #c0392b; letter-spacing: 5px; font-weight: bold;">${otp}</h2>
             <p>This code is valid for 5 minutes. If this wasn't you, please change your password immediately.</p>`
        );

        await sendMail({ to: email, subject: "Admin Login Verification", html: emailContent });

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

        // 1. Validate OTP
        if (otpStore[email] && parseInt(otpStore[email]) === parseInt(otp)) {
            
            // 2. Get Admin Details
            const admin = await Admin.findOne({ email });
            
            // 3. Clear OTP to prevent reuse
            delete otpStore[email]; 

            // 4. Generate Token
            const token = jwt.sign(
                { id: admin._id, role: admin.role }, 
                process.env.JWT_SECRET || "fallback_secret_key", 
                { expiresIn: "1d" }
            );

            res.json({ 
                success: true, 
                token, 
                admin: { username: admin.username, email: admin.email, role: admin.role } 
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


const otpStore = {}; 

// 1. REGISTER (Updated to use Multer for Multipart Upload)

app.post("/api/auth/register", uploadSignature.single('digitalSignature'), async (req, res) => {
    try {
        const data = req.body;

        // --- STEP 1: VALIDATION ---
        // 1. Check for Digital Signature File
        if (!req.file) {
            return res.status(400).json({ 
                success: false, 
                message: "Digital Signature file is required." 
            });
        }
        const signatureUrl = req.file.path; 

        // 2. Check Password
        if (!data.password) {
            return res.status(400).json({ success: false, message: "Password is required" });
        }

        // 3. Check if user exists
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
            isActive: true, // Auto-active for now, or false if you want admin approval first

            // --- LEGAL & SECURITY FIELDS ---
            digitalSignature: signatureUrl, 
            termsAcceptedAt: new Date(),
            termsAcceptedIP: clientIp
        });

        // --- STEP 3: SAVE TO DB ---
        await user.save();

        // --- STEP 4: PREPARE EMAILS (Your Custom Templates) ---

        // A. Welcome Email Content
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

        // B. Admin Alert Content (Table Format)
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
                <a href="https://kalyanashobha-admin.vercel.app" style="background-color: #2c3e50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; font-size: 14px;">Go to Admin Dashboard</a>
             </div>`
        );

        // --- STEP 5: SEND EMAILS (Parallel & Awaited for Vercel) ---
        
        // 1. Prepare Promises
        const sendUserMail = sendMail({ 
            to: user.email, 
            subject: "Welcome to KalyanaShobha Matrimony", 
            html: userWelcomeContent 
        });

        const sendAdminMail = sendMail({ 
            to: process.env.EMAIL_USER, // Sends to your admin email
            subject: `New User: ${user.uniqueId} (${user.firstName})`, 
            html: adminAlertContent 
        });

        // 2. Wait for completion
        try {
            await Promise.all([sendUserMail, sendAdminMail]);
            console.log("Registration emails sent successfully.");
        } catch (emailError) {
            console.error("Email Sending Failed:", emailError);
            // We do not return an error response here, so the user flow isn't interrupted.
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

app.post("/api/auth/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, message: "Email not found" });
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore[email] = otp;

        // Email Template
        const htmlTemplate = generateEmailTemplate(
            "Password Reset OTP",
            `<p>Your OTP for resetting password is:</p>
             <h2 style="letter-spacing: 3px; color:#2c3e50;">${otp}</h2>
             <p>This OTP is valid for <strong>5 minutes</strong>.</p>`
        );

        await sendMail({
            to: email,
            subject: "Reset Password - OTP Verification",
            html: htmlTemplate
        });

        res.json({
            success: true,
            message: "OTP sent to your registered email."
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});


// ======================== VERIFY OTP =========================

app.post("/api/auth/verify-otp", (req, res) => {
    const { email, otp } = req.body;

    if (!otpStore[email]) {
        return res.status(400).json({ success: false, message: "OTP not requested or expired" });
    }

    if (otpStore[email] !== otp) {
        return res.status(400).json({ success: false, message: "Invalid OTP" });
    }

    // OTP matched - allow reset
    otpStore[email] = "VERIFIED";

    res.json({ success: true, message: "OTP verified successfully" });
});


// ======================== RESET PASSWORD =========================

app.post("/api/auth/reset-password", async (req, res) => {
    try {
        const { email, newPassword } = req.body;

        if (!otpStore[email] || otpStore[email] !== "VERIFIED") {
            return res.status(400).json({ success: false, message: "OTP not verified" });
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

        // Delete used OTP
        delete otpStore[email];

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
        const user = await User.findById(req.userId).select("-password -otp");
        if (!user) return res.status(404).json({ success: false, message: "User not found" });
        
        res.json({ success: true, user });
    } catch (e) {
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// 2. Update Profile Details
app.put("/api/user/update-profile", verifyUser, async (req, res) => {
    try {
        const { 
            firstName, lastName, religion, caste, subCommunity, 
            state, city, education, jobRole, annualIncome, 
            height, diet, maritalStatus, aboutMe 
        } = req.body;

        // Create an update object (prevent updating sensitive fields like email/password here)
        const updateData = {
            firstName, lastName, religion, caste, subCommunity,
            state, city, highestQualification: education, jobRole, annualIncome,
            height, diet, maritalStatus, aboutMe
        };

        const updatedUser = await User.findByIdAndUpdate(
            req.userId, 
            { $set: updateData },
            { new: true } // Return the updated document
        ).select("-password");

        res.json({ success: true, message: "Profile Updated", user: updatedUser });
    } catch (e) {
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
        
        // 1. Find user by email ONLY (Removed isActive: true check here)
        const user = await User.findOne({ email }); 
        
        // 2. If user doesn't exist at all
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        // 3. SPECIFIC CHECK: If user exists but is restricted (isActive is false)
        if (!user.isActive) {
            return res.status(403).json({ 
                success: false, 
                message: "ACCESS DENIED: Your account has been restricted by Admin." 
            });
        }

        // 4. Validate Password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ success: false, message: "Invalid credentials" });

        // 5. Generate OTP (Rest of your logic remains same)
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = otp;
        setTimeout(() => delete otpStore[email], 300000); 

        const emailContent = generateEmailTemplate(
            "Login Authentication",
            `<p>You have requested to log in to your account.</p>
             <p>Your One-Time Password (OTP) is:</p>
             <h2 style="color: #2c3e50; letter-spacing: 5px;">${otp}</h2>
             <p>This code is valid for 5 minutes. Do not share this code with anyone.</p>`
        );

        await sendMail({ to: email, subject: "Your Login OTP", html: emailContent });
        res.json({ success: true, message: "OTP sent to email." });

    } catch (e) { 
        res.status(500).json({ success: false, message: e.message }); 
    }
});


app.post("/api/auth/login-verify", async (req, res) => {
    try {
        const { email, otp } = req.body;
        if (otpStore[email] && parseInt(otpStore[email]) === parseInt(otp)) {
            const user = await User.findOne({ email });
            delete otpStore[email]; 
            const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || "fallback_secret_key", { expiresIn: "7d" });
            res.json({ success: true, token, user });
        } else {
            res.status(400).json({ success: false, message: "Invalid or Expired OTP" });
        }
    } catch (e) { res.status(500).json({ success: false }); }
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
            Interest.countDocuments({ status: 'Accepted' })
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
            await sendMail({ to: user.email, subject: "Profile Status: Approved", html: emailContent });

        } else if (action === 'reject') {
            user.isApproved = false; user.rejectionReason = reason;
            const emailContent = generateEmailTemplate(
                "Profile Update Required",
                `<p>We reviewed your profile but could not approve it at this time.</p>
                 <p><strong>Reason:</strong> ${reason}</p>
                 <p>Please log in and update your profile information or photos accordingly to be reconsidered.</p>`
            );
            await sendMail({ to: user.email, subject: "Action Required: Profile Update", html: emailContent });

        } else if (action === 'block') { user.isActive = false; }
          else if (action === 'unblock') { user.isActive = true; }

        await user.save();
        res.json({ success: true, message: `User ${action}ed` });
    } catch (e) { res.status(500).json({ success: false }); }
});




// ====================================================================
// NEW: SPECIFIC ADVANCED SEARCH API
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
            religion, caste, subCommunity,
            // Professional
            education, occupation
        } = req.body;

        let query = {};

        // 1. Exact Match Fields
        if (memberId) query.uniqueId = { $regex: memberId, $options: 'i' };
        if (gender) query.gender = gender;
        if (maritalStatus) query.maritalStatus = maritalStatus;
        if (religion) query.religion = religion;
        if (caste) query.caste = { $regex: caste, $options: 'i' };
        if (subCommunity) query.subCommunity = { $regex: subCommunity, $options: 'i' };
        if (country) query.country = { $regex: country, $options: 'i' };
        if (state) query.state = { $regex: state, $options: 'i' };
        if (city) query.city = { $regex: city, $options: 'i' };
        
        // 2. Professional (Partial Matches)
        if (education) query.highestQualification = { $regex: education, $options: 'i' };
        if (occupation) query.jobRole = { $regex: occupation, $options: 'i' };

        // 3. Age Calculation (Converting Age to Date of Birth range)
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

// 1. Create Agent (With Password Hash & Code Gen)
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
        res.json({ success: true, message: "Agent created", agent });
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

// 1. POST: Create a new Vendor (Handles single, multiple, or no images)
app.post("/api/admin/vendors", verifyAdmin, uploadVendor.array("images", 5), async (req, res) => {
  try {
    // Safely check if images were uploaded. If yes, map to their Cloudinary URLs.
    const images = req.files && req.files.length > 0 
      ? req.files.map(file => file.path) 
      : [];

    const { businessName, category, description, contactNumber, priceRange } = req.body;

    // Basic Validation
    if (!businessName || !category || !contactNumber) {
      return res.status(400).json({ success: false, message: "Business Name, Category, and Contact Number are required." });
    }

    const vendor = new Vendor({
      businessName,
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
            






// ====================================================================
// E. PAYMENTS & INTERESTS
// ====================================================================

// 1. Submit Payment (User) - UPDATED WITH DUPLICATE CHECK
app.post("/api/payment/registration/submit", verifyUser, uploadPayment.single("screenshot"), async (req, res) => {
    try {
        // --- NEW LOGIC START: Check for existing pending request ---
        const existingPayment = await PaymentRegistration.findOne({ 
            userId: req.userId, 
            status: 'PendingVerification' 
        });

        if (existingPayment) {
            return res.json({ 
                success: false, 
                message: "You have already submitted a payment request. Please wait for admin verification.", 
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

        const emailContent = generateEmailTemplate(
            "Payment Received",
            `<p>We have received your payment submission of <strong>Rs. ${amount}</strong>.</p>
             <p>Our team will verify the transaction details (UTR: ${utrNumber}) within 24 hours.</p>
             <p>You will be notified once your membership is activated.</p>`
        );

        // ---------------------------------------------------------
        // CORRECTION START: Wait for emails to send parallelly
        // ---------------------------------------------------------

        // 1. Create the promises (start sending)
        const sendUserMail = sendMail({ 
            to: user.email, 
            subject: "Payment Submission Received", 
            html: emailContent 
        });

        const sendAdminMail = sendMail({ 
            to: process.env.EMAIL_USER, 
            subject: "New Membership Payment", 
            html: `<p>User ${user.firstName} (ID: ${user.uniqueId}) paid ${amount}. Please verify in dashboard.</p>` 
        });

        // 2. Wait for both to complete
        // This ensures emails are actually sent before the response closes the connection
        try {
            await Promise.all([sendUserMail, sendAdminMail]);
            console.log("Payment emails sent successfully.");
        } catch (emailError) {
            console.error("Warning: Payment emails failed, but DB record saved.", emailError);
        }

        // ---------------------------------------------------------
        // CORRECTION END
        // ---------------------------------------------------------

        res.json({ success: true, message: "Submitted successfully", status: "PendingVerification" });

    } catch (e) { 
        console.error(e);
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
                await sendMail({ to: user.email, subject: "Membership Activated", html: emailContent });
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
                await sendMail({ to: user.email, subject: "Action Required: Payment Issue", html: emailContent });
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
            to: process.env.EMAIL_USER, 
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

// 6. User Responds to Interest
app.post("/api/user/interest/respond", verifyUser, async (req, res) => {
    try {
        const { interestId, action } = req.body;
        
        // Populate fields to get Names and Emails
        const interest = await Interest.findById(interestId)
            .populate('senderId', 'firstName lastName email')
            .populate('receiverId', 'firstName lastName email');

        if (!interest) {
            return res.status(404).json({ success: false, message: "Interest not found" });
        }

        // Security check: Ensure the person responding is actually the Receiver
        if (interest.receiverId._id.toString() !== req.userId) {
            return res.status(403).json({ success: false, message: "Not your request" });
        }

        // Get the Receiver's Name (The person responding)
        const receiverName = `${interest.receiverId.firstName} ${interest.receiverId.lastName}`;

        if (action === "accept") {
            interest.status = "Accepted";
            
            // 1. SAVE TO DB FIRST (Critical)
            await interest.save();

            const senderContent = generateEmailTemplate(
                "Interest Accepted",
                `<p>Good news! <strong>${receiverName}</strong> has accepted your interest request.</p>
                 <p>You may now view their contact details on your dashboard.</p>`
            );

            // 2. SEND EMAIL (Wait for it)
            try {
                await sendMail({ to: interest.senderId.email, subject: "Interest Request Accepted", html: senderContent });
                console.log("Acceptance email sent.");
            } catch (emailErr) {
                console.error("Failed to send acceptance email:", emailErr);
            }

        } else {
            interest.status = "Declined";

            // 1. SAVE TO DB FIRST
            await interest.save();

            const senderContent = generateEmailTemplate(
                "Interest Update",
                `<p><strong>${receiverName}</strong> has declined your interest request.</p>
                 <p>We encourage you to continue searching for other suitable matches.</p>`
            );

            // 2. SEND EMAIL (Wait for it)
            try {
                await sendMail({ to: interest.senderId.email, subject: "Interest Request Update", html: senderContent });
                console.log("Decline email sent.");
            } catch (emailErr) {
                console.error("Failed to send decline email:", emailErr);
            }
        }
        
        res.json({ success: true, message: "Response submitted successfully" });

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
            status: { $in: ['PendingUser', 'Accepted', 'Declined'] } 
        })
        // 1. ADD 'mobileNumber' and 'email' HERE so the DB actually returns them
        .populate('senderId', 'firstName lastName uniqueId photos jobRole city state annualIncome dob mobileNumber email')
        .sort({ date: -1 });

        // 2. OPTIONAL BUT RECOMMENDED: Hide details if not 'Accepted' (Security)
        const formattedRequests = requests.map(req => {
            const isAccepted = req.status === 'Accepted';
            
            // We clone the sender object to avoid modifying the DB document directly
            const senderData = req.senderId.toObject(); 
            
            if (!isAccepted) {
                senderData.mobileNumber = "Locked";
                senderData.email = "Locked";
            }
            
            return {
                ...req.toObject(),
                senderId: senderData
            };
        });

        res.json({ success: true, count: formattedRequests.length, data: formattedRequests });
    } catch (e) {
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// 2. Get "Sent" Interests (Requests I sent to OTHERS)
app.get("/api/user/interests/sent", verifyUser, async (req, res) => {
    try {
        // Find interests where I am the SENDER
        const sentRequests = await Interest.find({ senderId: req.userId })
        .populate('receiverId', 'firstName lastName uniqueId photos mobileNumber email') // We need contact info if Accepted
        .sort({ date: -1 });

        // Transform data to hide contact info unless status is 'Accepted'
        const formattedRequests = sentRequests.map(req => {
            const isAccepted = req.status === 'Accepted';
            return {
                _id: req._id,
                status: req.status,
                date: req.date,
                receiverProfile: {
                    name: `${req.receiverId.firstName} ${req.receiverId.lastName}`,
                    photo: req.receiverId.photos[0] || null,
                    // LOGIC: Only show phone/email if Accepted
                    mobile: isAccepted ? req.receiverId.mobileNumber : "Locked",
uniqueId: req.receiverId.uniqueId, 
                    email: isAccepted ? req.receiverId.email : "Locked"
                }
            };
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


// 3. Register a User (Manual Entry by Agent) - *** FIXED ENUM & FIELDS ***
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

        // 3. Create User Object (Mapping ALL fields explicitly to ensure safety)
        const user = new User({
            // --- Basic Fields ---
            profileFor: data.profileFor,
            gender: data.gender,
            firstName: data.firstName,
            lastName: data.lastName,
            dob: data.dob,
            
            // --- Religion & Community ---
            religion: data.religion,
            community: data.community, // React frontend sends 'caste' as 'community'
            caste: data.caste,         // Optional sub-caste
            subCommunity: data.subCommunity,

            // --- Location ---
            country: data.country,
            state: data.state,
            city: data.city,

            // --- Personal ---
            maritalStatus: data.maritalStatus,
            height: data.height, // Ensure this is a number in frontend
            diet: data.diet,

            // --- Education & Work (Previously Missing) ---
            highestQualification: data.highestQualification,
            collegeName: data.collegeName,
            workType: data.workType, // 'Private', 'Govt', etc.
            jobRole: data.jobRole,
            companyName: data.companyName,
            annualIncome: data.annualIncome,

            // --- Contact & Auth ---
            email: data.email,
            mobileNumber: data.mobileNumber,
            password: hashedPassword,
            
            // --- System Fields ---
            uniqueId: uniqueId,
            isActive: true, // Agent created profiles are active by default (but might need approval)
            isApproved: false, // Still needs Admin Approval
            isPaidMember: false,

            // --- REFERRAL LINKING (FIXED ENUM) ---
            referredByAgentId: agent._id,
            referredByAgentName: agent.name,
            referralType: 'manual' // FIXED: Was 'manual_entry', causing the error
        });

        // 4. Save to DB
        await user.save();

        // 5. Send Welcome Email
        const userWelcomeContent = generateEmailTemplate(
            "Welcome to KalyanaShobha",
            `<p>Dear ${user.firstName},</p>
             <p>Your profile has been created by our agent <strong>${agent.name}</strong>.</p>
             <p><strong>Profile ID:</strong> ${user.uniqueId}</p>
             <p><strong>Login Password:</strong> ${data.password}</p>
             <p>Please login to your dashboard to view matches.</p>`
        );
        sendMail({ to: user.email, subject: "Profile Created via Agent", html: userWelcomeContent });

        res.json({ success: true, message: "User registered successfully under your referral." });

    } catch (e) {
        console.error("Agent Reg Error:", e);
        // Return the specific error message (like Validation failed)
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
            sendMail({ to: user.email, subject: "Account Status Update"
                      , html: emailContent });
        } else {
             const emailContent = generateEmailTemplate(
                "Account Access Restored",
                `<p>Your account restriction has been removed.</p>
                 <p>You can now log in to your dashboard.</p>`
            );
            sendMail({ to: user.email, subject: "Account Status Update", html: emailContent });
        }

        res.json({ success: true, message: `User successfully ${actionWord}` });

    } catch (e) {
        console.error("Restriction API Error:", e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});


// ====================================================================
// USER DASHBOARD: SECURE FEED (Logic on Server)
// ====================================================================
app.get("/api/user/dashboard/feed", verifyUser, async (req, res) => {
    try {
        // 1. Get Logged-in User
        const currentUser = await User.findById(req.userId);
        if (!currentUser) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        // 2. Determine Opposite Gender
        const targetGender = currentUser.gender === 'Male' ? 'Female' : 'Male';

        // 3. Build Query
        // Rule: "Free users won't appear in search" -> so we filter targets by isPaidMember: true
        const query = {
            gender: targetGender,
            isApproved: true,
            isActive: true,
            isPaidMember: true,       // Only show paid members in the feed
            _id: { $ne: req.userId }  // Exclude self
        };

        // 4. Check Viewer Status
        const isViewerPaid = currentUser.isPaidMember;

        // 5. Fetch Profiles (Securely Limit Data)
        let profilesQuery = User.find(query)
            .select('firstName lastName dob highestQualification subCommunity city state maritalStatus photos')
            .sort({ createdAt: -1 });

        // SECURITY: If viewer is FREE, ONLY fetch 2 profiles from Database.
        if (!isViewerPaid) {
            profilesQuery = profilesQuery.limit(2);
        }

        const profiles = await profilesQuery;

        // 6. Get Total Count (Optional: To show "100+ more profiles" on the lock card)
        const totalMatches = await User.countDocuments(query);

        // 7. Format Data
        const formattedProfiles = profiles.map(p => {
            let age = "N/A";
            if (p.dob) {
                const diff = Date.now() - new Date(p.dob).getTime();
                const ageDate = new Date(diff);
                age = Math.abs(ageDate.getUTCFullYear() - 1970);
            }

            return {
                id: p._id,
                name: `${p.firstName} ${p.lastName}`,
                age: age,
                education: p.highestQualification || "Not Specified",
                subCommunity: p.subCommunity || "Not Specified",
                location: `${p.city}, ${p.state}`,
                status: p.maritalStatus,
                photo: p.photos && p.photos.length > 0 ? p.photos[0] : null
            };
        });

        res.json({ 
            success: true, 
            isPremium: isViewerPaid, // Send status to frontend
            count: formattedProfiles.length,
            totalAvailable: totalMatches, // Total profiles existing in DB (for the "Unlock" card text)
            data: formattedProfiles 
        });

    } catch (e) {
        console.error("Dashboard Feed Error:", e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});


// ====================================================================
// USER SEARCH: ADVANCED FILTERS
// ====================================================================
app.post("/api/user/search-matches", verifyUser, async (req, res) => {
    try {
        const currentUser = await User.findById(req.userId);
        const targetGender = currentUser.gender === 'Male' ? 'Female' : 'Male';

        const {
            // Ranges
            minAge, maxAge,
            minHeight, maxHeight,
            minSalary, // Assuming you store annualIncome as string or number, this might need parsing
            
            // Strict / Exact Matches
            education, // "highestQualification" in DB
            subCommunity, // "caste" or "subCommunity" in DB
            maritalStatus,
            
            // Specifics
            occupation, // "jobRole" in DB
            searchId    // "uniqueId"
        } = req.body;

        // 1. Base Query (Opposite Gender + Approved)
        let query = {
            gender: targetGender,
            isApproved: true,
            isActive: true
        };

        // --- A. ID SEARCH (If ID is provided, ignore other filters) ---
        if (searchId) {
            query.uniqueId = { $regex: searchId, $options: 'i' }; // Case insensitive search
        } else {
            // --- B. AGE FILTER (Calculated via DOB) ---
            if (minAge || maxAge) {
                const today = new Date();
                query.dob = {};
                
                // Example: If Max Age is 30, they must be born BEFORE 30 years ago
                if (maxAge) {
                    const maxDate = new Date(new Date().setFullYear(today.getFullYear() - maxAge));
                    query.dob.$gte = maxDate; 
                }
                // Example: If Min Age is 20, they must be born AFTER 20 years ago
                if (minAge) {
                    const minDate = new Date(new Date().setFullYear(today.getFullYear() - minAge));
                    query.dob.$lte = minDate;
                }
            }

            // --- C. HEIGHT FILTER ---
            if (minHeight || maxHeight) {
                query.height = {};
                if (minHeight) query.height.$gte = parseFloat(minHeight);
                if (maxHeight) query.height.$lte = parseFloat(maxHeight);
            }

            // --- D. STRICT MATCHES (Education & Community) ---
            // If user sends education, match exactly. 
            if (education) {
                query.highestQualification = education; 
            }
            
            // Logic for "Caste both same only" (As per your request)
            // If the user selects a caste, use that. If not, you can optionally restrict to their own caste.
            if (subCommunity) {
                // Search by the provided caste/subCommunity
                query.$or = [
                    { caste: subCommunity },
                    { subCommunity: subCommunity }
                ];
            }

            // --- E. OTHER FILTERS ---
            if (maritalStatus) {
                query.maritalStatus = maritalStatus;
            }

            if (occupation) {
                // Partial match for job (e.g., searching "Soft" finds "Software Engineer")
                query.jobRole = { $regex: occupation, $options: 'i' };
            }
            
            // Salary Logic (Handling string ranges like "5-10 LPA" is complex, 
            // assuming strict string match or basic logic here)
            if (minSalary) {
                query.annualIncome = { $ne: null }; // Basic check to ensure field exists
                // Note: To do numeric salary comparison, annualIncome in DB should be a Number.
                // If it is a string like "100000", we can try:
                // query.annualIncome = { $gte: minSalary }; 
            }
        }

        // 2. Execute Query
        const results = await User.find(query)
            .select('firstName lastName uniqueId dob highestQualification caste subCommunity jobRole maritalStatus annualIncome height city state photos');

        // 3. Format Response (Add Age Calculation)
        const formattedResults = results.map(p => {
            let age = "N/A";
            if (p.dob) {
                const diff = Date.now() - new Date(p.dob).getTime();
                const ageDate = new Date(diff);
                age = Math.abs(ageDate.getUTCFullYear() - 1970);
            }

            return {
                id: p._id,
                uniqueId: p.uniqueId,
                name: `${p.firstName} ${p.lastName}`,
                age: age,
                height: p.height,
                education: p.highestQualification,
                community: `${p.caste} / ${p.subCommunity}`,
                occupation: p.jobRole,
                salary: p.annualIncome,
                maritalStatus: p.maritalStatus,
                location: `${p.city}, ${p.state}`,
                photo: p.photos && p.photos.length > 0 ? p.photos[0] : null
            };
        });

        res.json({ 
            success: true, 
            count: formattedResults.length, 
            data: formattedResults 
        });

    } catch (e) {
        console.error("Advanced Search Error:", e);
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



const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));



