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
// Ensure these files exist in your 'models' folder
const User = require('./models/User');
const Agent = require('./models/Agent');
const Vendor = require('./models/Vendor');
const Interest = require('./models/Interest');
const PaymentRegistration = require('./models/PaymentRegistration');
const PaymentInterest = require('./models/PaymentInterest');
const Admin = require('./models/Admin');

const app = express();
app.use(cors());
app.use(express.json());

// ---------------- DB CONNECTION ----------------
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("MongoDB Connected"))
    .catch(err => console.error("MongoDB Error:", err));

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

// ---------------- EMAIL SYSTEM (PROFESSIONAL) ----------------
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

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
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header"><h1>KalyanaShobha</h1></div>
            <div class="content">
                <h2 style="color: #2c3e50; border-bottom: 2px solid #eee;">${title}</h2>
                ${bodyContent}
                <p style="margin-top: 30px;">Sincerely,<br>The KalyanaShobha Team</p>
            </div>
            <div class="footer"><p>&copy; ${new Date().getFullYear()} KalyanaShobha. All rights reserved.</p></div>
        </div>
    </body>
    </html>`;
};

async function sendMail({ to, subject, html }) {
    try {
        await transporter.sendMail({
            from: `"KalyanaShobha" <${process.env.EMAIL_USER}>`,
            to, subject, html
        });
        return true;
    } catch (err) {
        console.error("MAIL ERROR:", err);
        return false;
    }
}

// ---------------- ID GENERATOR ----------------
async function generateUserId(state) {
    let code = "IN";
    if (state && state.toLowerCase() === "telangana") code = "TG";
    if (state && state.toLowerCase() === "maharashtra") code = "MAR";
    
    // Using regex to match state case-insensitively for accurate count
    const count = await User.countDocuments({ state: { $regex: new RegExp(`^${state}$`, 'i') } });
    return `${code}-${String(count + 1).padStart(5, '0')}`;
}

// ---------------- MIDDLEWARE: SECURITY ----------------
const verifyAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ success: false, message: "No token provided" });

    // Handle "Bearer <token>" format
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7, authHeader.length) : authHeader;

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
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ success: false, message: "No token provided" });

    // Handle "Bearer <token>" format
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7, authHeader.length) : authHeader;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || "fallback_secret_key");
        req.userId = decoded.id;
        next();
    } catch (err) {
        return res.status(401).json({ success: false, message: "Unauthorized" });
    }
};

// ====================================================================
// A. ADMIN AUTHENTICATION
// ====================================================================

app.post("/api/admin/seed", async (req, res) => {
    try {
        const existingAdmin = await Admin.findOne({ email: "admin@kalyanashobha.com" });
        if (existingAdmin) return res.status(400).json({ message: "Admin already exists" });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash("admin123", salt);

        const admin = new Admin({
            username: "SuperAdmin", email: "admin@kalyanashobha.com",
            password: hashedPassword, role: "SuperAdmin"
        });
        await admin.save();
        res.json({ success: true, message: "Admin Created" });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post("/api/admin/auth/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const admin = await Admin.findOne({ email });
        if (!admin) return res.status(404).json({ success: false, message: "Admin not found" });

        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) return res.status(400).json({ success: false, message: "Invalid credentials" });

        const token = jwt.sign({ id: admin._id, role: admin.role }, process.env.JWT_SECRET || "fallback_secret_key", { expiresIn: "1d" });
        res.json({ success: true, token, admin: { username: admin.username, email: admin.email, role: admin.role } });
    } catch (e) { res.status(500).json({ success: false, message: "Server Error" }); }
});

// ====================================================================
// B. USER AUTH (Register & Secure Login with OTP)
// ====================================================================
const otpStore = {}; // For Login
const registerOtpStore = {}; // For Registration

// 1. REGISTER INIT: Validate Email, store data, send OTP
app.post("/api/auth/register-init", async (req, res) => {
    try {
        const data = req.body;

        // Check if user exists already
        const exists = await User.findOne({ email: data.email });
        if (exists) {
            return res.status(400).json({ success: false, message: "Email already registered" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000);

        // Store data temporarily
        registerOtpStore[data.email] = {
            otp,
            data,
            expiresAt: Date.now() + 5 * 60 * 1000
        };

        // Auto delete after 5 mins
        setTimeout(() => delete registerOtpStore[data.email], 300000);

        const emailContent = generateEmailTemplate(
            "Complete Your Registration",
            `<p>Use the OTP below to complete your registration:</p>
             <h2 style="letter-spacing:5px;">${otp}</h2>
             <p>This OTP is valid for 5 minutes.</p>`
        );

        await sendMail({
            to: data.email,
            subject: "Your Registration OTP",
            html: emailContent
        });

        res.json({ success: true, message: "OTP sent to your Gmail" });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// 2. REGISTER VERIFY: Validate OTP, create User
app.post("/api/auth/register-verify", async (req, res) => {
    try {
        const { email, otp } = req.body;

        const session = registerOtpStore[email];
        if (!session) return res.status(400).json({ success: false, message: "OTP expired or not found" });

        if (parseInt(otp) !== session.otp) return res.status(400).json({ success: false, message: "Invalid OTP" });

        const userData = session.data;
        delete registerOtpStore[email]; // Cleanup

        // Generate ID and Hash Password
        const uniqueId = await generateUserId(userData.state);
        const hashedPassword = await bcrypt.hash(userData.password, 10);

        // Create User
        const newUser = new User({
            ...userData,
            password: hashedPassword,
            uniqueId,
            isVerified: true, // Mark as verified
            photos: []
        });

        await newUser.save();

        const emailContent = generateEmailTemplate(
            "Welcome to KalyanaShobha",
            `<p>Your registration is successful.</p>
             <p>Your Profile ID: <strong>${uniqueId}</strong></p>`
        );

        sendMail({ to: email, subject: "Registration Successful", html: emailContent });

        res.json({ success: true, message: "Account created successfully. Please login.", user: newUser });

    } catch (err) {
        console.error("REGISTRATION ERROR:", err);
        res.status(500).json({ success: false, message: err.message || "Registration Failed" });
    }
});

// 3. LOGIN INIT
app.post("/api/auth/login-init", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email }); 
        
        if (!user) return res.status(404).json({ success: false, message: "User not found" });
        if (user.isActive === false) return res.status(403).json({ success: false, message: "Account blocked by Admin" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ success: false, message: "Invalid credentials" });

        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = otp;
        setTimeout(() => delete otpStore[email], 300000); 

        const emailContent = generateEmailTemplate(
            "Login Authentication",
            `<p>Your Login OTP is:</p><h2 style="letter-spacing: 5px;">${otp}</h2>`
        );

        await sendMail({ to: email, subject: "Your Login OTP", html: emailContent });
        res.json({ success: true, message: "OTP sent to email." });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 4. LOGIN VERIFY
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

// 5. UPLOAD PHOTOS
app.post("/api/user/upload-photos", verifyUser, uploadProfile.array("photos", 3), async (req, res) => {
    try {
        if (!req.files || req.files.length === 0) return res.status(400).json({ success: false, message: "No photos uploaded" });

        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        const uploadedPhotos = req.files.map(f => f.path);
        user.photos = uploadedPhotos; // Replacing photos
        await user.save();

        res.json({ success: true, message: "Photos uploaded successfully", photos: user.photos });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// ====================================================================
// C. SEARCH (Public)
// ====================================================================
app.post("/api/users/search", async (req, res) => {
    try {
        const { 
            gender, minAge, maxAge, minHeight, maxHeight, 
            religion, caste, education, state, city, diet 
        } = req.body;

        let query = { isApproved: true, isActive: true };

        if (gender) query.gender = gender;
        if (religion) query.religion = religion;
        if (caste) query.caste = caste;
        if (education) query.highestQualification = education;
        if (state) query.state = state;
        if (city) query.city = city;
        if (diet) query.diet = diet;

        // AGE CALCULATION LOGIC
        if (minAge || maxAge) {
            query.dob = {};
            const today = new Date();
            // To be at least X years old, you must be born BEFORE today - X years
            if (minAge) query.dob.$lte = new Date(today.getFullYear() - minAge, today.getMonth(), today.getDate());
            // To be at most Y years old, you must be born AFTER today - Y years
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
// D. ADMIN DASHBOARD & MANAGEMENT (SECURE)
// ====================================================================

app.get("/api/admin/stats", verifyAdmin, async (req, res) => {
    try {
        const [users, males, females, paid, pending, agents, vendors] = await Promise.all([
            User.countDocuments({}),
            User.countDocuments({ gender: 'Male' }),
            User.countDocuments({ gender: 'Female' }),
            User.countDocuments({ isPaidMember: true }),
            User.countDocuments({ isApproved: false }),
            Agent.countDocuments({}),
            Vendor.countDocuments({})
        ]);
        res.json({ success: true, stats: { users, males, females, paid, pending, agents, vendors } });
    } catch (e) { res.status(500).json({ success: false }); }
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
                `<p>We are pleased to inform you that your profile has been successfully verified.</p>`
            );
            await sendMail({ to: user.email, subject: "Profile Status: Approved", html: emailContent });

        } else if (action === 'reject') {
            user.isApproved = false; user.rejectionReason = reason;
            const emailContent = generateEmailTemplate(
                "Profile Update Required",
                `<p>We reviewed your profile but could not approve it.</p><p>Reason: ${reason}</p>`
            );
            await sendMail({ to: user.email, subject: "Action Required", html: emailContent });

        } else if (action === 'block') { user.isActive = false; }
          else if (action === 'unblock') { user.isActive = true; }

        await user.save();
        res.json({ success: true, message: `User ${action}ed` });
    } catch (e) { res.status(500).json({ success: false }); }
});

// ---------------- AGENTS & VENDORS ----------------
app.post("/api/admin/agents", verifyAdmin, async (req, res) => {
    try {
        const agent = new Agent(req.body);
        await agent.save();
        res.json({ success: true, agent });
    } catch (e) { res.status(500).json({ success: false }); }
});
app.get("/api/admin/agents", verifyAdmin, async (req, res) => {
    const agents = await Agent.find();
    res.json({ success: true, agents });
});
app.delete("/api/admin/agents/:id", verifyAdmin, async (req, res) => {
    await Agent.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});

app.post("/api/admin/vendors", verifyAdmin, uploadVendor.array("images", 3), async (req, res) => {
    try {
        const images = req.files.map(f => f.path);
        const vendor = new Vendor({ ...req.body, images, isApproved: true });
        await vendor.save();
        res.json({ success: true, vendor });
    } catch (e) { res.status(500).json({ success: false }); }
});
app.get("/api/admin/vendors", verifyAdmin, async (req, res) => {
    const vendors = await Vendor.find();
    res.json({ success: true, vendors });
});
app.delete("/api/admin/vendors/:id", verifyAdmin, async (req, res) => {
    await Vendor.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});

// ====================================================================
// E. PAYMENTS & INTERESTS
// ====================================================================

// 1. Submit Payment (User)
app.post("/api/payment/registration/submit", verifyUser, uploadPayment.single("screenshot"), async (req, res) => {
    try {
        const { amount, utrNumber } = req.body;
        const user = await User.findById(req.userId);

        const payment = new PaymentRegistration({
            userId: req.userId, amount, utrNumber, screenshotUrl: req.file.path
        });
        await payment.save();

        const emailContent = generateEmailTemplate(
            "Payment Received",
            `<p>We have received your payment submission of <strong>Rs. ${amount}</strong> (UTR: ${utrNumber}).</p>`
        );
        sendMail({ to: user.email, subject: "Payment Submission Received", html: emailContent });

        res.json({ success: true, message: "Submitted" });
    } catch (e) { res.status(500).json({ success: false }); }
});

// 2. Admin Verify Registration
app.post("/api/admin/payment/registration/verify", verifyAdmin, async (req, res) => {
    try {
        const { paymentId, action } = req.body;
        const payment = await PaymentRegistration.findById(paymentId);
        const user = await User.findById(payment.userId);

        if (action === "approve") {
            payment.status = "Success"; user.isPaidMember = true;
            await payment.save(); await user.save();
            await sendMail({ to: user.email, subject: "Membership Activated", html: generateEmailTemplate("Membership Activated", "<p>Your Paid Membership is now Active.</p>") });
        } else {
            payment.status = "Rejected"; await payment.save();
            await sendMail({ to: user.email, subject: "Payment Failed", html: generateEmailTemplate("Payment Failed", "<p>We could not verify your payment.</p>") });
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false }); }
});


// 3. Submit Interest (User)
app.post("/api/interest/submit-proof", verifyUser, uploadPayment.single("screenshot"), async (req, res) => {
    try {
        const { receiverId, amount, utrNumber } = req.body;
        const user = await User.findById(req.userId);
        
        const payment = new PaymentInterest({
            senderId: req.userId, receiverId, amount, utrNumber, screenshotUrl: req.file.path
        });
        await payment.save();

        const interest = new Interest({
            senderId: req.userId, receiverId, paymentId: payment._id, status: "PendingPaymentVerification"
        });
        await interest.save();

        sendMail({ 
            to: user.email, 
            subject: "Interest Submitted", 
            html: generateEmailTemplate("Interest Received", `<p>We received your interest request for user ID: ${receiverId}.</p>`) 
        });

        res.json({ success: true, message: "Interest Request Submitted" });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// 4. Admin Verify Interest
app.post("/api/admin/payment/interest/verify", verifyAdmin, async (req, res) => {
    try {
        const { paymentId, action } = req.body;
        const payment = await PaymentInterest.findById(paymentId).populate('senderId');
        const interest = await Interest.findOne({ paymentId });

        if (action === "approve") {
            payment.status = "Success"; interest.status = "PendingAdmin";
            await sendMail({ to: payment.senderId.email, subject: "Payment Verified", html: generateEmailTemplate("Payment Verified", "<p>Your payment is verified. Request under review.</p>") });
        } else {
            payment.status = "Rejected"; interest.status = "Rejected";
            await sendMail({ to: payment.senderId.email, subject: "Payment Rejected", html: generateEmailTemplate("Payment Rejected", "<p>Invalid transaction details.</p>") });
        }
        await payment.save(); await interest.save();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false }); }
});

// 5. Admin Approve Interest Content
app.post("/api/admin/interest/approve-content", verifyAdmin, async (req, res) => {
    try {
        const { interestId, action } = req.body;
        const interest = await Interest.findById(interestId).populate('receiverId').populate('senderId');

        if (action === "approve") {
            interest.status = "PendingUser";
            sendMail({ to: interest.senderId.email, subject: "Request Forwarded", html: generateEmailTemplate("Request Forwarded", `<p>Forwarded to ${interest.receiverId.username}.</p>`) });
            sendMail({ to: interest.receiverId.email, subject: "New Interest", html: generateEmailTemplate("New Interest", `<p>You have a new interest from ${interest.senderId.username}.</p>`) });
        } else {
            interest.status = "Rejected";
            sendMail({ to: interest.senderId.email, subject: "Request Rejected", html: generateEmailTemplate("Request Rejected", "<p>Content did not meet guidelines.</p>") });
        }
        await interest.save();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false }); }
});

// 6. User Responds to Interest
app.post("/api/user/interest/respond", verifyUser, async (req, res) => {
    try {
        const { interestId, action } = req.body;
        const interest = await Interest.findById(interestId).populate('senderId').populate('receiverId');

        if (interest.receiverId._id.toString() !== req.userId) return res.status(403).json({ message: "Unauthorized" });

        if (action === "accept") {
            interest.status = "Accepted";
            sendMail({ to: interest.senderId.email, subject: "Accepted!", html: generateEmailTemplate("Accepted", `<p>${interest.receiverId.username} accepted your request.</p>`) });
        } else {
            interest.status = "Declined";
            sendMail({ to: interest.senderId.email, subject: "Declined", html: generateEmailTemplate("Declined", `<p>${interest.receiverId.username} declined your request.</p>`) });
        }
        await interest.save();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false }); }
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
            res.status(403).json({ success: false, message: "Contact Locked. Interest must be accepted first." });
        }
    } catch (e) { res.status(500).json({ success: false }); }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
