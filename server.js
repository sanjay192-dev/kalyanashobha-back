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
app.use(cors());
app.use(express.json());

// ---------------- DB CONNECTION ----------------
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected"))
    .catch(err => console.error("❌ MongoDB Error:", err));

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

// ---------------- EMAIL HELPER ----------------
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

async function sendMail({ to, subject, html }) {
    try {
        await transporter.sendMail({
            from: `"KalyanaShobha" <${process.env.EMAIL_USER}>`,
            to, subject,
            html: `<div style="font-family:sans-serif;padding:20px;border:1px solid #ddd;">${html}</div>`
        });
        return true;
    } catch (err) {
        console.error("❌ MAIL ERROR:", err);
        return false;
    }
}

// ---------------- ID GENERATOR ----------------
async function generateUserId(state) {
    let code = "IN";
    if (state && state.toLowerCase() === "telangana") code = "TG";
    if (state && state.toLowerCase() === "maharashtra") code = "MAR";
    const count = await User.countDocuments({ state });
    return `${code}-${String(count + 1).padStart(5, '0')}`;
}

// ---------------- MIDDLEWARE: SECURITY ----------------

// 1. Verify Admin Token
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

// 2. Verify User Token
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

// ====================================================================
// A. ADMIN AUTHENTICATION
// ====================================================================

// Seed First Admin (Run Once)
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

// Admin Login
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

// Change Admin Password (SECURE)
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

// ====================================================================
// B. USER AUTH (Register & Secure Login with OTP)
// ====================================================================
const otpStore = {}; // Memory Store for OTPs

// 1. Register User (Hashes Password)
app.post("/api/auth/register", uploadProfile.array("photos", 3), async (req, res) => {
    try {
        const data = req.body;
        const photos = req.files.map(f => f.path);
        const uniqueId = await generateUserId(data.state);

        // Hash Password
        if (!data.password) return res.status(400).json({ success: false, message: "Password is required" });
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(data.password, salt);

        const user = new User({ ...data, password: hashedPassword, uniqueId, photos });
        await user.save();

        sendMail({ to: user.email, subject: "Welcome!", html: `<p>Registration Successful. ID: <b>${uniqueId}</b></p>` });
        res.json({ success: true, user });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 2. Login Step 1: Validate Password & Send OTP
app.post("/api/auth/login-init", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email, isActive: true }); // Only active users
        if (!user) return res.status(404).json({ success: false, message: "User not found or blocked" });

        // Check Password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ success: false, message: "Invalid credentials" });

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = otp;
        setTimeout(() => delete otpStore[email], 300000); // 5 mins expiry

        // Send OTP
        await sendMail({ 
            to: email, 
            subject: "Login OTP Code", 
            html: `<h3>Your Login OTP is: <b style="color:blue">${otp}</b></h3><p>Valid for 5 minutes.</p>` 
        });

        res.json({ success: true, message: "Password verified. OTP sent to email." });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 3. Login Step 2: Verify OTP & Get Token
app.post("/api/auth/login-verify", async (req, res) => {
    try {
        const { email, otp } = req.body;
        
        if (otpStore[email] && parseInt(otpStore[email]) === parseInt(otp)) {
            const user = await User.findOne({ email });
            delete otpStore[email]; // Clear OTP
            
            // Generate User Token
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
            state, city, diet, maritalStatus 
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
// D. ADMIN DASHBOARD & MANAGEMENT (SECURE)
// ====================================================================

// Stats
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

// User Management
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
            await sendMail({ to: user.email, subject: "Profile Approved ✅", html: "Your profile is now live!" });
        } else if (action === 'reject') {
            user.isApproved = false; user.rejectionReason = reason;
            await sendMail({ to: user.email, subject: "Profile Rejected ❌", html: `Reason: ${reason}.` });
        } else if (action === 'block') { user.isActive = false; }
          else if (action === 'unblock') { user.isActive = true; }

        await user.save();
        res.json({ success: true, message: `User ${action}ed` });
    } catch (e) { res.status(500).json({ success: false }); }
});

// Agents (Secure)
app.post("/api/admin/agents", verifyAdmin, async (req, res) => {
    try {
        const agent = new Agent(req.body);
        await agent.save();
        res.json({ success: true, agent });
    } catch (e) { res.status(500).json({ success: false }); }
});
app.delete("/api/admin/agents/:id", verifyAdmin, async (req, res) => {
    await Agent.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});
app.get("/api/admin/agents", verifyAdmin, async (req, res) => {
    const agents = await Agent.find();
    res.json({ success: true, agents });
});

// Vendors (Secure)
app.post("/api/admin/vendors", verifyAdmin, uploadVendor.array("images", 3), async (req, res) => {
    try {
        const images = req.files.map(f => f.path);
        const vendor = new Vendor({ ...req.body, images, isApproved: true });
        await vendor.save();
        res.json({ success: true, vendor });
    } catch (e) { res.status(500).json({ success: false }); }
});
app.delete("/api/admin/vendors/:id", verifyAdmin, async (req, res) => {
    await Vendor.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});
app.get("/api/admin/vendors", verifyAdmin, async (req, res) => {
    const vendors = await Vendor.find();
    res.json({ success: true, vendors });
});

// ====================================================================
// E. PAYMENTS & INTERESTS
// ====================================================================

// 1. Submit Payment (User) - Requires User Token
app.post("/api/payment/registration/submit", verifyUser, uploadPayment.single("screenshot"), async (req, res) => {
    try {
        const { amount, utrNumber } = req.body;
        const payment = new PaymentRegistration({
            userId: req.userId, amount, utrNumber, screenshotUrl: req.file.path
        });
        await payment.save();
        sendMail({ to: process.env.EMAIL_USER, subject: "Membership Payment", html: `User ${req.userId} paid ${amount}` });
        res.json({ success: true, message: "Submitted" });
    } catch (e) { res.status(500).json({ success: false }); }
});

// 2. Admin Verify Registration (SECURE)
app.post("/api/admin/payment/registration/verify", verifyAdmin, async (req, res) => {
    try {
        const { paymentId, action } = req.body;
        const payment = await PaymentRegistration.findById(paymentId);
        const user = await User.findById(payment.userId);

        if (action === "approve") {
            payment.status = "Success"; user.isPaidMember = true;
            await payment.save(); await user.save();
            sendMail({ to: user.email, subject: "Membership Activated", html: "Approved!" });
        } else {
            payment.status = "Rejected"; await payment.save();
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false }); }
});

// 3. Submit Interest (User) - Requires User Token
app.post("/api/interest/submit-proof", verifyUser, uploadPayment.single("screenshot"), async (req, res) => {
    try {
        const { receiverId, amount, utrNumber } = req.body;
        const payment = new PaymentInterest({
            senderId: req.userId, receiverId, amount, utrNumber, screenshotUrl: req.file.path
        });
        await payment.save();

        const interest = new Interest({
            senderId: req.userId, receiverId, paymentId: payment._id, status: "PendingPaymentVerification"
        });
        await interest.save();

        res.json({ success: true, message: "Interest Request Submitted" });
    } catch (e) { res.status(500).json({ success: false }); }
});

// 4. Admin Verify Interest Payment (SECURE)
app.post("/api/admin/payment/interest/verify", verifyAdmin, async (req, res) => {
    try {
        const { paymentId, action } = req.body;
        const payment = await PaymentInterest.findById(paymentId);
        const interest = await Interest.findOne({ paymentId });

        if (action === "approve") {
            payment.status = "Success"; interest.status = "PendingAdmin";
        } else {
            payment.status = "Rejected"; interest.status = "Rejected";
        }
        await payment.save(); await interest.save();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false }); }
});

// 5. Admin Approve Interest Content (SECURE)
app.post("/api/admin/interest/approve-content", verifyAdmin, async (req, res) => {
    const { interestId, action } = req.body;
    const interest = await Interest.findById(interestId).populate('receiverId');
    if (action === "approve") {
        interest.status = "PendingUser";
        sendMail({ to: interest.receiverId.email, subject: "New Interest", html: "Someone liked your profile." });
    } else {
        interest.status = "Rejected";
    }
    await interest.save();
    res.json({ success: true });
});

// 6. User Responds to Interest (User Token)
app.post("/api/user/interest/respond", verifyUser, async (req, res) => {
    const { interestId, action } = req.body;
    const interest = await Interest.findById(interestId).populate('senderId');

    // Security check: Ensure the person responding is actually the receiver
    if (interest.receiverId.toString() !== req.userId) {
        return res.status(403).json({ success: false, message: "Not your request" });
    }

    if (action === "accept") {
        interest.status = "Accepted";
        sendMail({ to: interest.senderId.email, subject: "Accepted!", html: "Contact details unlocked." });
    } else {
        interest.status = "Declined";
    }
    await interest.save();
    res.json({ success: true });
});

// 7. Get Contact Details (User Token)
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port`))