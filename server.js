
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

// ---------------- ID GENERATOR ----------------
async function generateUserId(state) {
    let code = "IN";
    if (state && state.toLowerCase() === "telangana") code = "TG";
    if (state && state.toLowerCase() === "maharashtra") code = "MAR";
    const count = await User.countDocuments({ state });
    return `${code}-${String(count + 1).padStart(5, '0')}`;
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
const otpStore = {}; 

app.post("/api/auth/register", uploadProfile.array("photos", 3), async (req, res) => {
    try {
        const data = req.body;
        const photos = req.files.map(f => f.path);
        const uniqueId = await generateUserId(data.state);

        if (!data.password) return res.status(400).json({ success: false, message: "Password is required" });
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(data.password, salt);

        const user = new User({ ...data, password: hashedPassword, uniqueId, photos });
        await user.save();

        const emailContent = generateEmailTemplate(
            "Welcome to KalyanaShobha",
            `<p>Thank you for registering with us. We are delighted to have you on board.</p>
             <p>Your unique Profile ID is: <strong>${uniqueId}</strong></p>
             <p>Our team will review your profile shortly. Once approved, your profile will be visible to potential matches.</p>`
        );

        sendMail({ to: user.email, subject: "Welcome to KalyanaShobha - Registration Successful", html: emailContent });
        res.json({ success: true, user });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post("/api/auth/login-init", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email, isActive: true }); 
        if (!user) return res.status(404).json({ success: false, message: "User not found or blocked" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ success: false, message: "Invalid credentials" });

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
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
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
            `<p>We have received your payment submission of <strong>Rs. ${amount}</strong>.</p>
             <p>Our team will verify the transaction details (UTR: ${utrNumber}) within 24 hours.</p>
             <p>You will receive a confirmation email once your membership is activated.</p>`
        );
        sendMail({ to: user.email, subject: "Payment Submission Received", html: emailContent });

        // Admin Alert (Simplified for internal)
        sendMail({ to: process.env.EMAIL_USER, subject: "New Membership Payment", html: `<p>User ${req.userId} paid ${amount}. Please verify.</p>` });

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

            const emailContent = generateEmailTemplate(
                "Membership Activated",
                `<p>We verified your payment successfully.</p>
                 <p>Your Paid Membership is now <strong>Active</strong>. You can now access premium features.</p>`
            );
            sendMail({ to: user.email, subject: "Membership Activated", html: emailContent });

        } else {
            payment.status = "Rejected"; await payment.save();
            const emailContent = generateEmailTemplate(
                "Payment Verification Failed",
                `<p>We could not verify your recent payment transaction.</p>
                 <p>Please check if the UTR number or screenshot provided was correct and try submitting again.</p>`
            );
            sendMail({ to: user.email, subject: "Action Required: Payment Issue", html: emailContent });
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false }); }
});


// 3. Submit Interest (User) - Both User and Admin receive emails
app.post("/api/interest/submit-proof", verifyUser, uploadPayment.single("screenshot"), async (req, res) => {
    try {
        const { receiverId, amount, utrNumber } = req.body;

        // 1. Fetch user details for the email
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

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

        // 4. Send Email to SENDER (Acknowledgment)
        const userEmailContent = generateEmailTemplate(
            "Interest Request Received",
            `<p>Dear ${user.username},</p>
             <p>We have received your interest request and the payment proof of <strong>Rs. ${amount}</strong>.</p>
             <p>Our administration team is currently verifying the transaction details (UTR: ${utrNumber}). Once verified, your interest will be forwarded to the recipient.</p>
             <p>Status: Payment Verification Pending</p>`
        );
        sendMail({ 
            to: user.email, 
            subject: "Notification: Interest Request Submitted", 
            html: userEmailContent 
        });

        // 5. Send Email to ADMIN (Action Required)
        const adminEmailContent = generateEmailTemplate(
            "Action Required: New Interest Payment",
            `<p>A new interest payment has been submitted for verification.</p>
             <p><strong>Sender ID:</strong> ${user.uniqueId}<br>
                <strong>UTR Number:</strong> ${utrNumber}<br>
                <strong>Amount:</strong> Rs. ${amount}</p>
             <p>Please log in to the Admin Dashboard to verify the screenshot and approve the request.</p>`
        );
        sendMail({ 
            to: process.env.EMAIL_USER, 
            subject: "Admin Alert: New Interest Verification Required", 
            html: adminEmailContent 
        });

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
        const payment = await PaymentInterest.findById(paymentId).populate('senderId'); // Populated for Email
        const interest = await Interest.findOne({ paymentId });

        if (action === "approve") {
            payment.status = "Success"; interest.status = "PendingAdmin";

            const emailContent = generateEmailTemplate(
                "Payment Verified",
                `<p>Your payment for the interest request has been verified.</p>
                 <p>Your request is now under final content review by our team.</p>`
            );
            await sendMail({ to: payment.senderId.email, subject: "Payment Successful", html: emailContent });

        } else {
            payment.status = "Rejected"; interest.status = "Rejected";

            const emailContent = generateEmailTemplate(
                "Payment Verification Failed",
                `<p>We were unable to verify your payment for the interest request.</p>
                 <p>Please ensure the transaction details are correct and submit again.</p>`
            );
            await sendMail({ to: payment.senderId.email, subject: "Payment Verification Issue", html: emailContent });
        }
        await payment.save(); await interest.save();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false }); }
});

// 5. Admin Approve Interest Content
app.post("/api/admin/interest/approve-content", verifyAdmin, async (req, res) => {
    try {
        const { interestId, action } = req.body;
        // Populate both to send emails
        const interest = await Interest.findById(interestId).populate('receiverId').populate('senderId');

        if (action === "approve") {
            interest.status = "PendingUser";

            // Mail to Sender
            const senderContent = generateEmailTemplate(
                "Request Forwarded",
                `<p>Your interest request has been approved by our team and forwarded to the profile of <strong>${interest.receiverId.username}</strong>.</p>
                 <p>You will be notified once they respond.</p>`
            );
            sendMail({ to: interest.senderId.email, subject: "Request Forwarded", html: senderContent });

            // Mail to Receiver
            const receiverContent = generateEmailTemplate(
                "New Interest Received",
                `<p>You have received a new interest from <strong>${interest.senderId.username}</strong>.</p>
                 <p>Please log in to your dashboard to view their profile and accept or decline this request.</p>`
            );
            sendMail({ to: interest.receiverId.email, subject: "New Interest Notification", html: receiverContent });

        } else {
            interest.status = "Rejected";
            const senderContent = generateEmailTemplate(
                "Request Status",
                `<p>Your interest request could not be forwarded as it did not meet our content guidelines.</p>`
            );
            sendMail({ to: interest.senderId.email, subject: "Interest Request Update", html: senderContent });
        }
        await interest.save();
        res.json({ success: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false });
    }
});

// 6. User Responds to Interest
app.post("/api/user/interest/respond", verifyUser, async (req, res) => {
    try {
        const { interestId, action } = req.body;
        const interest = await Interest.findById(interestId).populate('senderId').populate('receiverId');

        // Security check
        if (interest.receiverId._id.toString() !== req.userId) {
            return res.status(403).json({ success: false, message: "Not your request" });
        }

        if (action === "accept") {
            interest.status = "Accepted";

            const senderContent = generateEmailTemplate(
                "Interest Accepted",
                `<p>Good news! <strong>${interest.receiverId.username}</strong> has accepted your interest request.</p>
                 <p>You may now view their contact details on your dashboard.</p>`
            );
            sendMail({ to: interest.senderId.email, subject: "Interest Request Accepted", html: senderContent });

        } else {
            interest.status = "Declined";

            const senderContent = generateEmailTemplate(
                "Interest Update",
                `<p><strong>${interest.receiverId.username}</strong> has declined your interest request.</p>
                 <p>We encourage you to continue searching for other suitable matches.</p>`
            );
            sendMail({ to: interest.senderId.email, subject: "Interest Request Update", html: senderContent });
        }
        await interest.save();
        res.json({ success: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false });
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));



