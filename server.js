// server.js
const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
require('dotenv').config();
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const multer = require("multer"); // Move multer import here
const path = require("path"); // Move path import here
const cors = require("cors");
const crypto = require("crypto");
const stripe = require('stripe')(process.env.STRIPE_KEY);
const nodemailer = require('nodemailer');
const otpGenerator = require('otp-generator');
const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const { request } = require("http");
const { update } = require("lodash");
const axios = require('axios');

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Connect to MongoDB 
    mongoose.connect(process.env.MONGODB_URL)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1); // Exit the process with a non-zero status code
  });
  
const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));

// User schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  userType: { type: String, required: true, enum: ["admin", "buyer", "seller"] },
  status: { type: String, enum: ['approved', 'rejected'], default: 'approved' },
  profilePicture: String,
  name: { type: String },
  buyerFields: {
    name: String,
    address: String,
    contactNumber: String
  },
  sellerFields: {
    companyName: String,
    contactPerson: String,
    contactNumber: String,
    name: String,
    businessName: String,
    businessAddress: String,
  },
  addresses: [{ type: mongoose.Schema.Types.ObjectId, ref: "Address" }],
  profilePicture: String,
  createdAt: { type: Date, default: Date.now },
  activities: [
    {
      title: { type: String, required: true },
      description: { type: String, required: true },
      timestamp: { type: Date, default: Date.now },
    },
  ],
  otp: String,
  otpExpires: Date,
  isVerified: { type: Boolean, default: false },
  resetToken: String,
  resetTokenExpires: Date,

});
const User = mongoose.model("User", userSchema);

// Category model
const categorySchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  categoryImage: { type: String, default: "" },
});
const Category = mongoose.model("Category", categorySchema);

// ItemType model
const itemTypeSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
});
const ItemType = mongoose.model("ItemType", itemTypeSchema);

// Brand model
const brandSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
});
const Brand = mongoose.model("Brand", brandSchema);

// Product schema
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  aboutThisItem: { type: String, default: '' },
  price: { type: Number, required: true },
  stock: { type: Number, required: true },
  discount: { type: Number, default: 0 },
  images: [{ type: String }],
  category: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Category",
    required: true,
  },
  itemType: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "ItemType",
    required: true,
  },
  brand: { type: mongoose.Schema.Types.ObjectId, ref: "Brand", required: true },
  seller: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  attributes: { type: Map, of: String }, // Dynamic field for product-specific attributes
  requiredAttributes: [{ type: String }] // Array of attribute names that are required for this product
});

const Product = mongoose.model('Product', productSchema);


// Mongoose Schema and Model
const soldSchema = new mongoose.Schema({
  productId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Product',
    required: true,
  },
  buyerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  },
  status: {
    type: Boolean,
    default: true,
  },
});

const Sold = mongoose.model('Sold', soldSchema);

// Cart Item schema
const cartItemSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  quantity: { type: Number, required: true, default: 1 },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  cartId: { type: String, required: true },
});

const CartItem = mongoose.model('CartItem', cartItemSchema);

// Address model
const addressSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  fullName: { type: String, required: true },
  phoneNumber: { type: String, required: true },
  pinCode: { type: String, required: true },
  locality: { type: String, required: true },
  address: { type: String, required: true },
  city: { type: String, required: true },
  state: { type: String, required: true },
  landmark: { type: String },
});

const Address = mongoose.model("Address", addressSchema);


// order model
const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  paymentMethod: { type: String, required: true },
  status: { type: String, required: true, default: 'pending' },
  deliveryStatus: { type: String, required: true, default: 'pending' },
  createdAt: { type: Date, default: Date.now }, // Add this line
  items: [
    {
      productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
      productName: { type: String, required: true },
      quantity: { type: Number, required: true },
      price: { type: Number, required: true },
      images: [String], // Make sure the images field is an array of strings
    },
  ],
});

const Order = mongoose.model('Order', orderSchema);

// Comment schema
const commentSchema = new mongoose.Schema({
  text: { type: String, required: true },
  author: {
    _id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true }
  },
  seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  buyerId: {
    _id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true }
  },
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  likeCount: { type: Number, default: 0 },
  dislikeCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  images: [{ type: String }],
  rating: { type: Number, required: true },
  likedBy: [{
    _id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: { type: String }
  }],
  dislikedBy: [{  // Add this field
    _id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: { type: String }
  }],
  reply: { type: String },
});

const Comment = mongoose.model('Comment', commentSchema);
// Activity schema
const activitySchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  description: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
});

const Activity = mongoose.model('Activity', activitySchema);

// Enable CORS for all routes
app.use(cors());

app.use(
  cors()
);


// Middleware for parsing request body
app.use(express.json());
// Middleware
app.use(express.urlencoded({ extended: true }));

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'categories',
    allowed_formats: ['jpg', 'png', 'jpeg'],
    public_id: (req, file) => `category_${Date.now()}_${file.originalname}`,
    flags: 'attachment',
  },
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024 }, // 5MB limit
});


app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Function to upload file to Cloudinary
// Function to upload file to Cloudinary
const uploadToCloudinary = (file) => {
  return new Promise((resolve, reject) => {
    console.log('Starting Cloudinary upload');
    const uploadStream = cloudinary.uploader.upload_stream(
      { folder: 'my_uploads' },
      (error, result) => {
        if (error) {
          console.error('Cloudinary upload error:', error);
          reject(error);
        } else {
          console.log('Cloudinary upload success:', result.secure_url);
          resolve(result.secure_url);
        }
      }
    );
    console.log('Created upload stream');
    
    if (!file.buffer || !Buffer.isBuffer(file.buffer)) {
      return reject(new Error('Invalid file format. Expected a file object with a buffer.'));
    }
    
    uploadStream.write(file.buffer);
    uploadStream.end();
    
    console.log('Written buffer to upload stream');
  });
};


const isSeller = (req, res, next) => {
  if (req.user.userType !== "seller") {
    return res.status(403).json({ message: "Unauthorized access" });
  }
  next();
};



// Created Admin
// Existing admin creation function
const createAdminUser = async () => {
  const adminEmail = "admin@1.com";
  const adminPassword = "123";

  try {
    const existingAdminUser = await User.findOne({ email: adminEmail });
    if (existingAdminUser) {
      if (!existingAdminUser.isVerified) {
        existingAdminUser.isVerified = true;
        existingAdminUser.status = "approved";
        await existingAdminUser.save();
        console.log("Admin user marked as verified");
      } else {
        console.log("Admin user already exists and is verified");
      }
      return;
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(adminPassword, saltRounds);

    const adminUser = new User({
      email: adminEmail,
      password: hashedPassword,
      userType: "admin",
      isVerified: true,
      status: "approved",
    });

    await adminUser.save();
    console.log("Admin user created successfully");
  } catch (error) {
    console.error("Error creating admin user:", error);
  }
};

// Add this line to call the function when the server starts
createAdminUser();


// ========= mail verification


const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false, 
  auth: {
    user: process.env.MAIL,
    pass:process.env.MAIL_PASSWORD ,
  },
});

// This should be the only declaration of sendEmail in your file
const sendEmail = async (to, subject, text) => {
  try {
    const info = await transporter.sendMail({
      from: '"PEM" <ashubhammagotra@gmail.com>',

      to: to,
      subject: subject,
      text: text,
    });
    console.log("Message sent: %s", info.messageId);
    return info;
  } catch (error) {
    console.error("Error sending email:", error);
    throw error;
  }
};

// OTP generation function
// OTP generation function
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}
// Registration route
app.post("/api/pem_users/register", async (req, res) => {
  const { email, password, userType, buyerFields, sellerFields } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const otp = generateOTP();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // OTP expires in 10 minutes

    const newUser = new User({
      email,
      password: hashedPassword,
      userType,
      buyerFields: userType === "buyer" ? buyerFields : {},
      sellerFields: userType === "seller" ? sellerFields : {},
      status: "pending",
      otp,
      otpExpires,
      isVerified: false,
    });

    await newUser.save();

    // Send OTP email
    try {
      await sendEmail(
        email,
        "Verify Your Email",
        `Your OTP for email verification is: ${otp}. It will expire in 10 minutes.`
      );
    } catch (emailError) {
      console.error("Failed to send OTP email:", emailError);
      // Instead of deleting the user, we'll keep the account but mark it as unverified
      return res.status(201).json({ 
        message: "User registered, but failed to send OTP email. Please contact support for verification.",
        requiresManualVerification: true
      });
    }

    res.status(201).json({ message: "OTP sent to your email. Please verify to complete registration." });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ message: "Internal server error", error: error.message });
  }
});

// OTP verification route
app.post("/api/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.isVerified) {
      return res.status(400).json({ message: "Email already verified" });
    }

    if (user.otp !== otp || user.otpExpires < new Date()) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    user.isVerified = true;
    user.status = "approved"; // Set status to approved after verification
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    res.status(200).json({ message: "Email verified successfully. You can now log in." });
  } catch (error) {
    console.error("OTP verification error:", error);
    res.status(500).json({ message: "Internal server error", error: error.message });
  }
});
// Route fo forget password 
app.post("/api/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const resetToken = generateOTP(); // Reusing the OTP function for simplicity
    const resetTokenExpires = new Date(Date.now() + 60 * 60 * 1000); // Token expires in 1 hour

    user.resetToken = resetToken;
    user.resetTokenExpires = resetTokenExpires;
    await user.save();

    // Send reset password email
    await sendEmail(
      email,
      "Reset Your Password",
      `Your password reset code is: ${resetToken}. It will expire in 1 hour. Use this code to reset your password.`
    );

    res.status(200).json({ message: "Password reset instructions sent to your email" });
  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({ message: "Internal server error", error: error.message });
  }
});
// Route fo reset password 
app.post("/api/reset-password", async (req, res) => {
  const { email, resetToken, newPassword } = req.body;

  try {
    const user = await User.findOne({
      email,
      resetToken,
      resetTokenExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired reset token" });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpires = undefined;
    await user.save();

    res.status(200).json({ message: "Password reset successfully" });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({ message: "Internal server error", error: error.message });
  }
});

// Login route
// Login route

app.post('/api/login', async (req, res) => {

  try {
  const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check user status
    if (user.status === 'rejected') {
      return res.status(403).json({ message: "Your account has been disabled. Please contact support." });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Special case for admin user
    if (user.userType === 'admin') {
      const token = jwt.sign({ userId: user._id, userType: user.userType }, process.env.JWT_SECRET_KEY, { expiresIn: '12h' });
      return res.status(200).json({ token: token, userType: user.userType, userData: user });
    }

    // For non-admin users, check if the email is verified
    if (!user.isVerified) {
      return res.status(403).json({ message: 'Email not verified. Please verify your email to log in.' });
    }

    const token = jwt.sign({ userId: user._id, userType: user.userType }, process.env.JWT_SECRET_KEY, { expiresIn: '12h' });

    res.status(200).json({ token: token, userType: user.userType, userData: user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Auth 

const authenticateToken = (req, res, next) => {
  const token = req.token;

  if (!token) {
    console.log('Token missing');
    return res.status(401).json({ message: 'Token missing' });
  }

  console.log('Verifying token:', token);

  jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
    if (err) {
      console.error('Token verification error:', err);
      return res.status(403).json({ message: 'Invalid token' });
    }

    console.log('Decoded user data:', decoded);

    if (decoded !== null) {
      console.log('Decoded user:', decoded);
      req.user = decoded;
      next();
    } else {
      console.error('Token verification failed: Decoded data is null');
      return res.status(403).json({ message: 'Invalid token' });
    }
  });
};
  // Middleware to extract token from headers
  const extractToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      req.token = authHeader.split(' ')[1];
    } else {
      req.token = null; // Set token to null if not provided
    }
    next();
  };
  app.use(extractToken);
 

  // =========================================================Adim Routes========================================

  // Route to fetch all users in  Admin page
  app.get("/api/admin_users", authenticateToken, async (req, res) => {
    try {
      if (req.user.userType !== "admin") {
        return res.status(403).json({ message: "Unauthorized access" });
      }
  
      const users = await User.find({}, { password: 0 }); // Exclude password field
      res.json(users);
    } catch (error) {
      console.error("Error fetching users:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Route to fetch all buyers
  app.get("/api/admin_buyers", authenticateToken, async (req, res) => {
    try {
      if (req.user.userType !== "admin") {
        return res.status(403).json({ message: "Unauthorized access" });
      }
  
      const buyers = await User.find({ userType: "buyer" }, { password: 0 }); // Exclude password field
      res.json(buyers);
    } catch (error) {
      console.error("Error fetching buyers:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Route to fetch all sellers
  app.get("/api/admin_sellers", authenticateToken, async (req, res) => {
    try {
      if (req.user.userType !== "admin") {
        return res.status(403).json({ message: "Unauthorized access" });
      }
  
      const sellers = await User.find({ userType: "seller" }, { password: 0 }); // Exclude password field
      res.json(sellers);
    } catch (error) {
      console.error("Error fetching sellers:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // Admin Route to update user status on off
app.put("/api/:userType/:userId/status", authenticateToken, async (req, res) => {
  try {
    console.log("Request URL:", req.url);
    console.log("Request params:", req.params);

    if (req.user.userType !== "admin") {
      return res.status(403).json({ message: "Unauthorized access" });
    }

    const { userType, userId } = req.params;
    const { isActive } = req.body;

    const user = await User.findOneAndUpdate(
      { _id: userId, userType },
      { status: isActive ? "approved" : "rejected" },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({ message: "User status updated successfully", user });
  } catch (error) {
    console.error("Error updating user status:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
  // Protected route for admin
  app.get("/api/admin", authenticateToken, (req, res) => {
    if (req.user.userType !== "admin") {
      return res.status(403).json({ message: "Unauthorized access" });
    }
  
    res.json({ message: "Welcome to the admin panel" });
  });
  
  // Protected route for sellers
  app.get("/api/sellers", authenticateToken, (req, res) => {
    if (req.user.userType !== "seller") {
      return res.status(403).json({ message: "Unauthorized access" });
    }
  
    res.json({ message: "Welcome to the seller panel" });
  });
  
  // Protected route for buyers
  app.get("/api/buyers", authenticateToken, (req, res) => {
    if (req.user.userType !== "buyer") {
      return res.status(403).json({ message: "Unauthorized access" });
    }
  
    res.json({ message: "Welcome to the buyer panel" });
  });
  
  // Logout route
  app.post("/api/logout", extractToken, (req, res) => {
    const token = req.token;
  
    res.json({ message: "Logout successful" });
  });

  // Route for fetching admin user data
app.get("/api/admins/:userId/profile", authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;

    if (req.user.userId !== userId) {
      return res.status(403).json({ message: "Unauthorized access" });
    }

    const admin = await User.findById(userId).populate('profilePicture');

    if (!admin) {
      return res.status(404).json({ message: "Admin user not found" });
    }

    const profilePictureUrl = admin.profilePicture
      ? `http://localhost:5002/${admin.profilePicture}`
      : '';

    const adminData = {
      ...admin.toObject(),
      profilePicture: profilePictureUrl,
    };

    res.json(adminData);
  } catch (error) {
    console.error("Error fetching admin profile:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Route to fetch all users in the Admin page
app.get("/api/admin_users", authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== "admin") {
      return res.status(403).json({ message: "Unauthorized access" });
    }

    const users = await User.find({}, { password: 0 }); // Exclude password field
    res.json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});



  // Fetch all the DATA OF Product like product/categories/ item / brands
  app.get("/api/admin/data", authenticateToken, async (req, res) => { 
    try {
      if (req.user.userType !== "admin") {
        return res.status(403).json({ message: "Unauthorized access" });
      }
  
      const [products, categories, itemTypes, brands] = await Promise.all([
        Product.find(),
        Category.find(),
        ItemType.find(),
        Brand.find(),
      ]);
  
      res.json({ products, categories, itemTypes, brands });
    } catch (error) {
      console.error("Error fetching admin data:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

 // Route to fetch all orders
app.get("/api/orders", authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== "admin") {
      return res.status(403).json({ message: "Unauthorized access" });
    }

    const orders = await Order.find()
      .populate({
        path: 'userId',
        select: 'email', // Specify the fields you want to include from the User model
      });

    res.json(orders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
// Route for toggling product status
app.put("/api/products/:id/toggle-status", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { isActive } = req.body;

    if (req.user.userType !== "admin") {
      return res.status(403).json({ message: "Unauthorized access" });
    }

    const updatedProduct = await Product.findByIdAndUpdate(
      id,
      { isActive: isActive },
      { new: true, runValidators: true }
    );

    if (!updatedProduct) {
      return res.status(404).json({ message: "Product not found" });
    }

    res.json(updatedProduct);
  } catch (error) {
    console.error("Error toggling product status:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Route for updating order status in admin
app.put("/api/orders/status", authenticateToken, async (req, res) => {
  try {
    const { orderId, deliveryStatus } = req.body;

    console.log('Received orderId:', orderId);
    console.log('Received deliveryStatus:', deliveryStatus);

    if (req.user.userType !== "admin") {
      return res.status(403).json({ message: "Unauthorized access" });
    }

    const updatedOrder = await Order.findByIdAndUpdate(
      orderId,
      { deliveryStatus: deliveryStatus },
      { new: true, runValidators: true }
    );

    if (!updatedOrder) {
      return res.status(404).json({ message: "Order not found" });
    }

    res.json(updatedOrder);
  } catch (error) {
    console.error("Error updating order delivery status:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// product detail commetns on off route 

  // ========================================                ===================================================================
  // ========================================Routes for SEller =======================================
  // ========================================                ===================================================================
  const isEntityUsed = async (entityType, entityId) => {
    const count = await Product.countDocuments({ [entityType]: entityId });
    return count > 0;
  };


  // route for update buyer profile  
  

  // route for updating seller profile 
  app.put("/api/sellers/:userId/profile", authenticateToken, upload.single('profilePicture'), async (req, res) => {
    console.log("Seller profile update request received");
    console.log("UserId from params:", req.params.userId);
    console.log("Request body:", req.body);
    console.log("Request file:", req.file);
  
    try {
      const requestedUserId = req.params.userId;
      const authenticatedUserId = req.user.userId;
  
      if (authenticatedUserId !== requestedUserId) {
        return res.status(403).json({
          message: "Unauthorized access: You can only update your own profile",
        });
      }
  
      const { name, email, businessName, contactNumber } = req.body;
  
      if (Object.keys(req.body).length === 0 && !req.file) {
        return res.status(400).json({ message: "No update data provided" });
      }
  
      const updateFields = {};
      if (name) updateFields['sellerFields.name'] = name.trim();
      if (businessName) updateFields['sellerFields.businessName'] = businessName.trim();
      if (email) updateFields.email = email.trim();
      if (contactNumber) updateFields['sellerFields.contactNumber'] = contactNumber.trim();
  
      if (req.file) {
        console.log("File received:", req.file);
        try {
          const secureUrl = await uploadToCloudinary(req.file);
          console.log("Cloudinary upload result:", secureUrl);
          updateFields.profilePicture = secureUrl;
        } catch (uploadError) {
          console.error("Cloudinary upload error:", uploadError);
          return res.status(500).json({ message: "Error uploading image" });
        }
      }
  
      const updatedUser = await User.findByIdAndUpdate(requestedUserId, updateFields, { new: true });
  
      if (!updatedUser) {
        return res.status(404).json({ message: "User not found" });
      }
  
      res.json({
        message: "Seller profile updated successfully",
        user: {
          name: updatedUser.sellerFields.name,
          email: updatedUser.email,
          businessName: updatedUser.sellerFields.businessName,
          contactNumber: updatedUser.sellerFields.contactNumber,
          profilePicture: updatedUser.profilePicture
        }
      });
  
    } catch (error) {
      console.error("Error updating seller profile:", error);
      res.status(500).json({
        message: "Internal server error",
        error: error.message,
        stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
      });
    }
  });
  
  // Route to fetch seller's profile
  
  app.get("/api/sellers/:sellerId/profile", authenticateToken, async (req, res) => {
    try {
      const { sellerId } = req.params;
  
      const seller = await User.findById(sellerId, { password: 0 })
        .populate("sellerFields");
  
      if (!seller) {
        return res.status(404).json({ message: "Seller not found" });
      }
  
      // Remove the local URL construction
      const sellerData = {
        ...seller.toObject(),
        profilePicture: seller.profilePicture || '',
      };
  
      res.json(sellerData);
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Internal server error" });
    }
  });

// Route to creaeting a categoires 
app.post("/api/categories", authenticateToken, async (req, res) => {
  try {
    console.log('Received category creation request:', req.body);
    const { name } = req.body;
    const newCategory = new Category({ name });
    await newCategory.save();
    console.log('Category created successfully:', newCategory);
    res.status(201).json(newCategory);
  } catch (error) {
    console.error("Error creating category:", error);
    res.status(500).json({ message: "Internal server error", error: error.message });
  }
});

  // Route for creating a new itemType 
  app.post("/api/itemTypes", async (req, res) => {
    const { name } = req.body;
  
    try {
      const newItemType = new ItemType({ name });
      await newItemType.save();
      res
        .status(201)
        .json({
          message: "Item type created successfully",
          itemType: newItemType,
        });
    } catch (error) {
      console.error("Error creating item type:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Route for creating a new brand
  app.post("/api/brands", async (req, res) => {
    const { name } = req.body;
  
    try {
      const newBrand = new Brand({ name });
      await newBrand.save();
      res
        .status(201)
        .json({ message: "Brand created successfully", brand: newBrand });
    } catch (error) {
      console.error("Error creating brand:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // Delete category
app.delete("/api/categories/:id", authenticateToken, async (req, res) => {
  try {
    const categoryId = req.params.id;
    
    const isUsed = await isEntityUsed('category', categoryId);
    if (isUsed) {
      return res.status(400).json({ message: "This category is used by one or more products and cannot be deleted." });
    }

    const deletedCategory = await Category.findByIdAndDelete(categoryId);
    if (!deletedCategory) {
      return res.status(404).json({ message: "Category not found" });
    }

    res.json({ message: "Category deleted successfully" });
  } catch (error) {
    console.error("Error deleting category:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Delete item type
app.delete("/api/itemTypes/:id", authenticateToken, async (req, res) => {
  try {
    const itemTypeId = req.params.id;
    
    const isUsed = await isEntityUsed('itemType', itemTypeId);
    if (isUsed) {
      return res.status(400).json({ message: "This item type is used by one or more products and cannot be deleted." });
    }

    const deletedItemType = await ItemType.findByIdAndDelete(itemTypeId);
    if (!deletedItemType) {
      return res.status(404).json({ message: "Item type not found" });
    }

    res.json({ message: "Item type deleted successfully" });
  } catch (error) {
    console.error("Error deleting item type:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Delete brand
app.delete("/api/brands/:id", authenticateToken, async (req, res) => {
  try {
    const brandId = req.params.id;
    
    const isUsed = await isEntityUsed('brand', brandId);
    if (isUsed) {
      return res.status(400).json({ message: "This brand is used by one or more products and cannot be deleted." });
    }

    const deletedBrand = await Brand.findByIdAndDelete(brandId);
    if (!deletedBrand) {
      return res.status(404).json({ message: "Brand not found" });
    }

    res.json({ message: "Brand deleted successfully" });
  } catch (error) {
    console.error("Error deleting brand:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

 // Route to fetch all categories

 
 app.get("/api/categories", async (req, res) => {
  try {
    const categories = await Category.find();
    const categoriesWithImageUrls = categories.map((category) => {
      const categoryObj = category.toObject();
      
      if (categoryObj.categoryImage) {
        // Remove the 'uploads/' prefix if it exists
        categoryObj.categoryImage = categoryObj.categoryImage.replace(/^uploads\//, '');
        
        // Ensure the URL is properly formatted
        if (!categoryObj.categoryImage.startsWith('http')) {
          categoryObj.categoryImage = `${process.env.BASE_URL}/uploads/${categoryObj.categoryImage}`;
        }
      }
      
      return categoryObj;
    });
    
    res.json(categoriesWithImageUrls);
  } catch (error) {
    console.error("Error fetching categories:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
  
  // Route to fetch all item types
  app.get("/api/itemTypes", async (req, res) => {
    try {
      const itemTypes = await ItemType.find();
      res.json(itemTypes);
    } catch (error) {
      console.error("Error fetching item types:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // Route to fetch all brands
  app.get("/api/brands", async (req, res) => {
    try {
      const brands = await Brand.find();
      res.json(brands);
    } catch (error) {
      console.error("Error fetching brands:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  

  
  // Route for deleting a product
  app.delete("/api/products/:id", async (req, res) => {
    try {
      const productId = req.params.id;
      const deletedProduct = await Product.findByIdAndDelete(productId);
  
      if (!deletedProduct) {
        return res.status(404).json({ message: "Product not found" });
      }
  
      res.json({ message: "Product deleted successfully" });
    } catch (error) {
      console.error("Error deleting product:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
  // route for udpating products
  // route for update the products
  app.put("/api/products/:id", authenticateToken, upload.array('newImages'), async (req, res) => {
    console.log('Update product route hit');
    console.log('Request body:', req.body);
    console.log('Files:', req.files);
  
    const productId = req.params.id;
    const updateData = req.body;
    const newImages = req.files;
  
    try {
      // Find the existing product
      const existingProduct = await Product.findById(productId);
      if (!existingProduct) {
        console.log('Product not found');
        return res.status(404).json({ message: 'Product not found' });
      }
  
      // Prepare the update object
      const updateObject = {
        name: updateData.name || existingProduct.name,
        description: updateData.description || existingProduct.description,
        price: updateData.price ? parseFloat(updateData.price) : existingProduct.price,
        stock: updateData.stock ? parseInt(updateData.stock) : existingProduct.stock,
        discount: updateData.discount ? parseFloat(updateData.discount) : existingProduct.discount,
        category: updateData.category || existingProduct.category,
        itemType: updateData.itemType || existingProduct.itemType,
        brand: updateData.brand || existingProduct.brand,
      };
  
      // Handle image updates
      let updatedImages = [...(existingProduct.images || [])];
  
      // Remove images that are marked for deletion
      if (updateData.imagesToDelete) {
        const imagesToDelete = Array.isArray(updateData.imagesToDelete) 
          ? updateData.imagesToDelete 
          : [updateData.imagesToDelete];
        
        for (const imageUrl of imagesToDelete) {
          const index = updatedImages.indexOf(imageUrl);
          if (index > -1) {
            updatedImages.splice(index, 1);
            try {
              await deleteFromCloudinary(imageUrl);
            } catch (deleteError) {
              console.error(`Failed to delete image from Cloudinary: ${imageUrl}`, deleteError);
            }
          }
        }
      }
  
      // Add new images
      if (newImages && newImages.length > 0) {
        console.log('New images detected');
        const uploadPromises = newImages.map(file => uploadToCloudinary(file));
        const uploadedImageUrls = await Promise.all(uploadPromises);
        updatedImages = [...updatedImages, ...uploadedImageUrls];
      }
  
      updateObject.images = updatedImages;
  
      console.log('Update object:', updateObject);
  
      // Update the product
      const updatedProduct = await Product.findByIdAndUpdate(
        productId,
        updateObject,
        { new: true, runValidators: true }
      ).populate('category itemType brand');
  
      if (!updatedProduct) {
        console.log('Failed to update product');
        return res.status(500).json({ message: 'Failed to update product' });
      }
  
      console.log('Updated product:', updatedProduct);
      res.json(updatedProduct);
    } catch (error) {
      console.error('Error in product update:', error);
      res.status(500).json({
        message: 'Internal server error',
        error: error.toString()
      });
    }
  });

  // Helper function to delete image from Cloudinary
  async function deleteFromCloudinary(imageUrl) {
    const publicId = imageUrl.split('/').pop().split('.')[0];
    await cloudinary.uploader.destroy(publicId);
  }
 
// route for adding product 
app.post("/api/products", authenticateToken, upload.array('images', 5), async (req, res) => {
  console.log('Files:', req.files);
  
  try {
    const {
      name,
      description,
      aboutThisItem,
      price,
      stock,
      discount,
      category,
      itemType,
      brand,
      attributes, // New field for custom attributes
    } = req.body;

    const sellerId = req.user.userId;

    // Validate required fields
    if (!name || !description || !price || !stock || !category || !itemType || !brand) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    let imageUrls = [];
    if (req.files && req.files.length > 0) {
      imageUrls = await Promise.all(req.files.map(file => uploadToCloudinary(file)));
    }

    // Parse attributes if they're sent as a string
    let parsedAttributes = {};
    if (attributes) {
      try {
        parsedAttributes = JSON.parse(attributes);
      } catch (error) {
        console.error("Error parsing attributes:", error);
        return res.status(400).json({ message: "Invalid attributes format" });
      }
    }

    const newProduct = new Product({
      name,
      description,
      aboutThisItem, // Make sure this line is present
      price: Number(price),
      stock: Number(stock),
      discount: Number(discount) || 0,
      images: imageUrls,
      category,
      itemType,
      brand,
      seller: sellerId,
      attributes: parsedAttributes,
    });

    const savedProduct = await newProduct.save();
    res.status(201).json({ message: "Product added successfully", product: savedProduct });
  } catch (error) {
    console.error("Error processing product data:", error);
    if (error.name === 'ValidationError') {
      return res.status(400).json({ message: "Validation error", error: error.message });
    }
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

  
// route for updating categories images 

app.put('/api/categories/:id', upload.single('image'), async (req, res) => {
  try {
    const { id } = req.params;
    const { name } = req.body;
    const updateData = { name };

    console.log('Updating category:', id);
    console.log('Request body:', req.body);
    console.log('File:', req.file);

    if (req.file) {
      // Upload file to Cloudinary
      const cloudinaryUpload = await new Promise((resolve, reject) => {
        const cldUploadStream = cloudinary.uploader.upload_stream(
          {
            folder: 'categories',
          },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );

        streamifier.createReadStream(req.file.buffer).pipe(cldUploadStream);
      });

      console.log('Cloudinary upload result:', cloudinaryUpload);

      updateData.categoryImage = cloudinaryUpload.secure_url;
      console.log('New image path:', updateData.categoryImage);
    } else {
      console.log('No file uploaded');
    }

    const updatedCategory = await Category.findByIdAndUpdate(
      id,
      updateData,
      { new: true }
    );

    if (!updatedCategory) {
      console.log('Category not found:', id);
      return res.status(404).json({ message: 'Category not found' });
    }

    console.log('Updated category:', updatedCategory);
    res.status(200).json(updatedCategory);
  } catch (error) {
    console.error('Error updating category:', error);
    res.status(500).json({ message: 'Error updating category', error: error.message });
  }
});


  // Route to fetch data for seller manage products
  app.get("/api/seller/data", authenticateToken, isSeller, async (req, res) => {
    try {
      const [products, categories, itemTypes, brands] = await Promise.all([
        Product.find({ seller: req.user.userId })
          .populate("category", "name")
          .populate("itemType", "name")
          .populate("brand", "name"),
        Category.find(),
        ItemType.find(),
        Brand.find(),
      ]);
  
      res.json({ products, categories, itemTypes, brands });
    } catch (error) {
      console.error("Error fetching seller data:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });


// Route to fetch seller comments
app.get('/api/seller/comments', authenticateToken, async (req, res) => {
  try {
    const sellerId = req.user.userId;
    console.log('Seller ID:', sellerId);

    const comments = await Comment.find()
      .populate('author', 'name')
      .populate({
        path: 'product',
        match: { seller: sellerId },
      })
      .populate('buyerId', 'name');

    const sellerComments = comments.filter((comment) => comment.product !== null);

    console.log('Fetched seller comments:', sellerComments);
    res.json(sellerComments);
  } catch (error) {
    console.error('Error fetching seller comments:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


// Route to seller reply to a  comment
app.post('/api/comments/:commentId/reply', authenticateToken, async (req, res) => {
  try {
    const { commentId } = req.params;
    const { reply } = req.body;

    console.log('Received commentId:', commentId);
    console.log('Received reply:', reply);
    console.log('Authenticated user:', req.user);

    const comment = await Comment.findById(commentId);
    if (!comment) {
      return res.status(404).json({ message: 'Comment not found' });
    }

    // Assuming the seller field in the comment is the user ID of the seller
    if (comment.seller.toString() !== req.user.userId) {
      return res.status(403).json({ message: 'You are not authorized to reply to this comment' });
    }

    comment.reply = reply;
    await comment.save();

    res.json(comment);
  } catch (error) {
    console.error('Error submitting reply:', error);
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});
  // ===============================================================================================================
  // ===============================================================BUYER==============================
  // ===============================================================================================================
  // Buyer profile update route

app.put("/api/buyers/:userId/profile", authenticateToken, upload.single('profilePicture'), async (req, res) => {
  console.log("1. Buyer profile update request received");
  console.log("2. UserId from params:", req.params.userId);
  console.log("3. Request body:", req.body);
  console.log("4. Request file:", req.file);

  try {
    const requestedUserId = req.params.userId;
    const authenticatedUserId = req.user.userId;

    console.log("5. Requested UserId:", requestedUserId);
    console.log("6. Authenticated UserId:", authenticatedUserId);

    if (authenticatedUserId !== requestedUserId) {
      console.log("7. Authorization failed: User IDs do not match");
      return res.status(403).json({
        message: "Unauthorized access: You can only update your own profile",
      });
    }

    console.log("7. Authorization passed");

    const { name, email, address, contactNumber } = req.body;

    console.log("8. Extracted data from request body:", { name, email, address, contactNumber });

    if (Object.keys(req.body).length === 0 && !req.file) {
      console.log("9. No update data provided");
      return res.status(400).json({ message: "No update data provided" });
    }

    const updateFields = {};
    if (name) updateFields['buyerFields.name'] = name.trim();
    if (address) updateFields['buyerFields.address'] = address.trim();
    if (email) updateFields.email = email.trim();
    if (contactNumber) updateFields['buyerFields.contactNumber'] = contactNumber.trim();

    console.log("10. Update fields prepared:", updateFields);

    if (req.file) {
      console.log("11. File received:", req.file);
      try {
        console.log("12. Attempting to upload to Cloudinary");
        const secureUrl = await uploadToCloudinary(req.file);
        console.log("13. Cloudinary upload result:", secureUrl);
        updateFields.profilePicture = secureUrl;
      } catch (uploadError) {
        console.error("14. Cloudinary upload error:", uploadError);
        return res.status(500).json({ message: "Error uploading image" });
      }
    }

    console.log("15. Attempting to update user in database");
    const updatedUser = await User.findByIdAndUpdate(requestedUserId, updateFields, { new: true });

    if (!updatedUser) {
      console.log("16. User not found in database");
      return res.status(404).json({ message: "User not found" });
    }

    console.log("16. User updated successfully");
    console.log("17. Updated user:", updatedUser);

    res.json({
      message: "Buyer profile updated successfully",
      user: {
        name: updatedUser.buyerFields.name,
        email: updatedUser.email,
        address: updatedUser.buyerFields.address,
        contactNumber: updatedUser.buyerFields.contactNumber,
        profilePicture: updatedUser.profilePicture
      }
    });

  } catch (error) {
    console.error("Error updating buyer profile:", error);
    res.status(500).json({
      message: "Internal server error",
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

  // route for realted products 
  app.get('/api/products/:id/related', async (req, res) => {
    try {
      const product = await Product.findById(req.params.id);
      if (!product) {
        return res.status(404).json({ message: 'Product not found' });
      }
  
      const relatedProducts = await Product.find({
        _id: { $ne: product._id },
        brand: product.brand,
        itemType: product.itemType,
        category: product.category
      }).limit(4);
  
      res.json(relatedProducts);
    } catch (error) {
      console.error('Error fetching related products:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });

  // Route for fetching buyer's profile
  app.get('/api/users/:userId/profile', authenticateToken, async (req, res) => {
    try {
      const { userId } = req.params;
      console.log('Received request for user profile with userId:', userId);
  
      // Find the user in the database based on the userId
      const user = await User.findById(userId)
        .populate('addresses')
        .lean();
  
      if (!user) {
        console.log('User not found');
        return res.status(404).json({ message: 'User not found' });
      }
  
      console.log('User found:', user);
  
      // Remove sensitive data if needed
      const { password, __v, ...userData } = user;
  
      res.json(userData);
    } catch (error) {
      console.error('Error fetching user profile:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
// Route to fetch orders for a specific user
app.get('/api/users/:userId/orders', authenticateToken, async (req, res) => {
  try {
    const userId = req.params.userId;

    // Check if the requested userId matches the authenticated user
    if (req.user.userId !== userId) {
      return res.status(403).json({ message: 'Unauthorized access' });
    }

    // Find the orders for the user
    const orders = await Order.find({ userId })
      .populate('items.productId', 'name price images')
      .lean();

    res.json(orders);
  } catch (error) {
    console.error('Error fetching user orders:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
// Route for fetching buyer's addresses
app.get('/api/users/:userId/addresses', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;

    // Find the addresses in the database based on the userId
    const addresses = await Address.find({ userId })
      .lean();

    res.json(addresses);
  } catch (error) {
    console.error('Error fetching user addresses:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Route for updating buyer's profile
app.put("/api/users/:userId/profile", authenticateToken, upload.single('profilePicture'), async (req, res) => {
  try {
    const { userId } = req.params;
    const { name, email, address, contactNumber } = req.body;
    const profilePicture = req.file ? req.file.path : '';

    if (req.user.userId !== userId) {
      return res.status(403).json({ message: "Unauthorized access" });
    }

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user.buyerFields.name = name;
    user.buyerFields.address = address;
    user.email = email;
    user.contactNumber = contactNumber;
    user.profilePicture = profilePicture;

  

    const updatedUser = await User.findByIdAndUpdate(
  userId,
  { buyerFields: { name, address }, email, contactNumber, profilePicture },
  { new: true }
);

console.log('Updated user:', updatedUser); // Log the updated user object

if (!updatedUser) {
  return res.status(404).json({ message: "User not found" });
}

res.json(updatedUser); 
  } catch (error) {
    console.error("Error updating buyer profile:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
  // Route for deleting category / item type / brands
  
  app.delete(
    "/api/categories/:id",
    authenticateToken,
    isSeller,
    async (req, res) => {
      try {
        const categoryId = req.params.id;
        const deletedCategory = await Category.findByIdAndDelete(categoryId);
  
        if (!deletedCategory) {
          return res.status(404).json({ message: "Category not found" });
        }
  
        // Check if the category is being used by any products
        const productsUsingCategory = await Product.find({
          category: categoryId,
        });
        if (productsUsingCategory.length > 0) {
          return res.status(400).json({
            message:
              "Cannot delete category. It is being used by one or more products.",
          });
        }
  
        res.json({ message: "Category deleted successfully" });
      } catch (error) {
        console.error("Error updating buyer profile:", error);
        if (error.name === 'CastError') {
          // Handle cast errors (e.g., invalid userId)
          return res.status(400).json({ message: 'Invalid user ID' });
        }
        // Handle other error cases as needed
        res.status(500).json({ message: 'Internal server error' });
      }
    }
  );
    
  app.delete(
    "/api/itemTypes/:id",
    authenticateToken,
    isSeller,
    async (req, res) => {
      try {
        const itemTypeId = req.params.id;
        const deletedItemType = await ItemType.findByIdAndDelete(itemTypeId);
  
        if (!deletedItemType) {
          return res.status(404).json({ message: "Item type not found" });
        }
  
        // Check if the item type is being used by any products
        const productsUsingItemType = await Product.find({
          itemType: itemTypeId,
        });
        if (productsUsingItemType.length > 0) {
          return res.status(400).json({
            message:
              "Cannot delete item type. It is being used by one or more products.",
          });
        }
  
        res.json({ message: "Item type deleted successfully" });
      } catch (error) {
        console.error("Error deleting item type:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    }
  );
  
  app.delete("/api/brands/:id", authenticateToken, isSeller, async (req, res) => {
    try {
      const brandId = req.params.id;
      const deletedBrand = await Brand.findByIdAndDelete(brandId);
  
      if (!deletedBrand) {
        return res.status(404).json({ message: "Brand not found" });
      }
  
      // Check if the brand is being used by any products
      const productsUsingBrand = await Product.find({ brand: brandId });
      if (productsUsingBrand.length > 0) {
        return res.status(400).json({
          message:
            "Cannot delete brand. It is being used by one or more products.",
        });
      }
  
      res.json({ message: "Brand deleted successfully" });
    } catch (error) {
      console.error("Error deleting brand:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  // route to fetch category products in home page categorywise
  app.get("/api/products", async (req, res) => {
    try {
      const categoryId = req.query.category;
  
      if (!categoryId) {
        return res.status(400).json({ message: "Category ID is required" });
      }
  
      const products = await Product.find({ category: categoryId })
        .populate("category", "name")
        .populate("itemType", "name")
        .populate("brand", "name");
  
      if (products.length === 0) {
        return res.status(404).json({ message: "No products found for the given category" });
      }
  
      res.json(products);
    } catch (error) {
      console.error("Error fetching products:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  

 // Route to fetch categories based on search term
app.get('/api/categories/search', async (req, res) => {
  try {
    const searchTerm = req.query.q || '';
    console.log('Search term (categories):', searchTerm);

    const categories = await Category.find({
      name: { $regex: new RegExp(searchTerm, 'i') },
    });

    console.log('Categories response data:', categories);
    res.json(categories);
  } catch (error) {
    console.error('Error searching categories:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
// Route to search for products
app.get('/api/search', async (req, res) => {
  try {
    const searchTerm = req.query.q || '';
    console.log('Search term (products):', searchTerm);

    const products = await Product.find({
      $or: [
        { name: { $regex: new RegExp(searchTerm, 'i') } },
        { description: { $regex: new RegExp(searchTerm, 'i') } },
      ],
    });

    console.log('Products found:', products.length);
    console.log('Products response data:', products);

    res.json(products);
  } catch (error) {
    console.error('Error searching products:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
// ==================detial page =======================add to cart 

app.post('/api/cart', authenticateToken, async (req, res) => {
  try {
    const { productId, quantity = 1 } = req.body;
    const userId = req.user.userId;

    console.log('Request body:', req.body); // Add this line
    console.log('User ID:', userId); // Add this line
    // Generate a unique cartId
    const cartId = `${userId}_${Date.now()}`;

    // Check if the product already exists in the cart
    const existingCartItem = await CartItem.findOne({ productId, userId });

    if (existingCartItem) {
      // If the product exists, update the quantity
      existingCartItem.quantity += quantity;
      await existingCartItem.save();
      return res.json(existingCartItem);
    }

    // Create a new cart item
    const newCartItem = new CartItem({ productId, quantity, userId, cartId });
    await newCartItem.save();

    res.status(201).json(newCartItem);
  } catch (error) {
    console.error('Error adding product to cart:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
// ===========================Fetching cart data =========

// Route to fetch cart data
app.get('/api/cart', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const cartItems = await CartItem.find({ userId })
      .populate({
        path: 'productId',
        populate: [
          { path: 'category', select: 'name' },
          { path: 'itemType', select: 'name' },
          { path: 'brand', select: 'name' },
          { path: 'seller', select: 'name' }
        ],
        select: 'name price discount images'
      })
      .lean();
      

    // Calculate total price and apply discounts
    const cartItemsWithTotals = cartItems.map(item => ({
      ...item,
      totalPrice: (item.productId.price * (1 - item.productId.discount / 100) * item.quantity).toFixed(2)
    }));

    res.json(cartItemsWithTotals);
  } catch (error) {
    console.error('Error fetching cart data:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


// route for upadating cart 

app.put('/api/cart/:cartItemId', authenticateToken, async (req, res) => {
  try {
    const { cartItemId } = req.params;
    const { quantity } = req.body;
    const userId = req.user.userId;

    const cartItem = await CartItem.findOneAndUpdate(
      { _id: cartItemId, userId },
      { quantity },
      { new: true }
    );

    if (!cartItem) {
      return res.status(404).json({ message: 'Cart item not found' });
    }

    res.json(cartItem);
  } catch (error) {
    console.error('Error updating cart item quantity:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
app.delete('/api/cart/:cartItemId', authenticateToken, async (req, res) => {
  try {
    const { cartItemId } = req.params;
    const userId = req.user.userId;

    const deletedCartItem = await CartItem.findOneAndDelete({ _id: cartItemId, userId });

    if (!deletedCartItem) {
      return res.status(404).json({ message: 'Cart item not found' });
    }

    res.json({ message: 'Cart item removed successfully' });
  } catch (error) {
    console.error('Error removing cart item:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Route to fetch order details by orderId
// Fetch order details by orderId
app.get('/orders/:orderId', authenticateToken, async (req, res) => {
  try {
    const orderId = req.params.orderId;
    const order = await Order.findById(orderId)
      .populate('items.productId', 'name price images')
      .lean();

    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    // Construct full URLs for product images
    const orderWithFullImageUrls = {
      ...order,
      items: order.items.map((item) => ({
        ...item,
        productId: {
          ...item.productId,
          images: item.productId.images.map((imagePath) => {
            if (imagePath.startsWith('http')) {
              return imagePath; // If the image path is already a full URL, return it as is
            } else {
              return `http://localhost:5002/${imagePath}`; // Otherwise, prepend the server URL
            }
          }),
        },
      })),
    };

    res.json(orderWithFullImageUrls);
  } catch (error) {
    console.error('Error fetching order details:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});



// ==============route to fetch the prodcut detials in detial

app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }
    res.json({ product: { ...product.toObject(), attributes: product.attributes } });
  } catch (error) {
    console.error('Error fetching product:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ===========================SAving user adress here ===========================================
// Route for fetching user profile and addresses
app.get("/api/users/:userId/profile", authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;

    if (req.user.userId !== userId) {
      return res.status(403).json({ message: "Unauthorized access" });
    }

    const user = await User.findById(userId, { password: 0, __v: 0 })
      .populate("addresses")
      .lean();

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
  } catch (error) {
    console.error("Error fetching user profile:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Route for saving a new address
app.post("/api/users/:userId/addresses", authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const { fullName, phoneNumber, pinCode, locality, address, city, state, landmark } = req.body;

    if (req.user.userId !== userId) {
      return res.status(403).json({ message: "Unauthorized access" });
    }

    const newAddress = new Address({
      userId,
      fullName,
      phoneNumber,
      pinCode,
      locality,
      address,
      city,
      state,
      landmark,
    });

    await newAddress.save();

    const user = await User.findByIdAndUpdate(
      userId,
      { $push: { addresses: newAddress._id } },
      { new: true }
    ).populate("addresses");

    res.status(201).json({ message: "Address added successfully", user });
  } catch (error) {
    console.error("Error saving address:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Route for updating an address
app.put("/api/users/:userId/addresses/:addressId", authenticateToken, async (req, res) => {
  try {
    const { userId, addressId } = req.params;
    const { fullName, phoneNumber, pinCode, locality, address, city, state, landmark } = req.body;

    if (req.user.userId !== userId) {
      return res.status(403).json({ message: "Unauthorized access" });
    }

    const updatedAddress = await Address.findOneAndUpdate(
      { _id: addressId, userId },
      { fullName, phoneNumber, pinCode, locality, address, city, state, landmark },
      { new: true }
    );

    if (!updatedAddress) {
      return res.status(404).json({ message: "Address not found" });
    }

    res.json(updatedAddress);
  } catch (error) {
    console.error("Error updating address:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
// Route for deleting an address
app.delete("/api/users/:userId/addresses/:addressId", authenticateToken, async (req, res) => {
  try {
    const { userId, addressId } = req.params;

    if (req.user.userId !== userId) {
      return res.status(403).json({ message: "Unauthorized access" });
    }

    const deletedAddress = await Address.findOneAndDelete({ _id: addressId, userId });

    if (!deletedAddress) {
      return res.status(404).json({ message: "Address not found" });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { $pull: { addresses: addressId } },
      { new: true }
    ).populate("addresses");

    res.json({ message: "Address deleted successfully", user });
  } catch (error) {
    console.error("Error deleting address:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
// Reverse geocoding
app.get('/api/reverse-geocode', async (req, res) => {
  try {
    const { latitude, longitude } = req.query;
    
    if (!latitude || !longitude) {
      return res.status(400).json({ message: 'Latitude and longitude are required' });
    }

    const openCageResponse = await axios.get(
      `https://api.opencagedata.com/geocode/v1/json?q=${latitude}+${longitude}&key=${process.env.OPENCAGE_API_KEY}&countrycode=in`
    );

    const result = openCageResponse.data.results[0].components;
    const pincode = result.postcode;

    // Use India Post API for more accurate results
    const indiaPostResponse = await axios.get(`https://api.postalpincode.in/pincode/${pincode}`);

    if (indiaPostResponse.data[0].Status === "Success") {
      const postOffice = indiaPostResponse.data[0].PostOffice[0];
      
      const addressDetails = {
        pinCode: pincode,
        locality: postOffice.Name,
        address: result.road || '',
        city: postOffice.Division,
        state: postOffice.State,
      };

      res.json(addressDetails);
    } else {
      throw new Error("Unable to fetch detailed location information");
    }
  } catch (error) {
    console.error('Error in reverse geocoding:', error);
    res.status(500).json({ message: 'Error fetching address details', error: error.message });
  }
});

// PIN code search endpoint
app.get('/pincode-search', async (req, res) => {
  try {
    const { pincode } = req.query;
    
    if (!pincode) {
      return res.status(400).json({ message: 'PIN code is required' });
    }

    const indiaPostResponse = await axios.get(`https://api.postalpincode.in/pincode/${pincode}`);

    if (indiaPostResponse.data[0].Status === "Success") {
      const postOffices = indiaPostResponse.data[0].PostOffice;
      
      const addressDetails = postOffices.map(po => ({
        pinCode: pincode,
        locality: po.Name,
        city: po.Division,
        state: po.State,
      }));

      res.json(addressDetails);
    } else {
      res.status(404).json({ message: "No results found for the given PIN code" });
    }
  } catch (error) {
    console.error('Error in PIN code search:', error);
    res.status(500).json({ message: 'Error fetching address details', error: error.message });
  }
});

// ==============================================================Payment=======================

app.post('/create-payment-intent', async (req, res) => {
  try {
    const { amount } = req.body;
    
    const paymentIntent = await stripe.paymentIntents.create({
      amount: amount * 100, // Amount in cents
      currency: 'usd',
    });
    
    res.status(200).json({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    console.error('Error creating payment intent:', error);
    res.status(500).json({ error: 'An error occurred while creating the payment intent.' });
  }
});

// route for order summary page to create order 
app.post('/api/create-order', authenticateToken, async (req, res) => {
  try {
    const { paymentMethod, paymentIntentId, userId, totalPrice, cartItems = [] } = req.body;

    const items = cartItems.map((item) => ({
      productId: item.productId._id || null,
      productName: item.productId.name || '',
      quantity: item.quantity || 0,
      price: item.productId.price || 0,
      images: item.productId.images || [],
    }));

    const newOrder = new Order({
      userId,
      amount: totalPrice,
      paymentMethod,
      paymentIntentId: paymentMethod === 'card' ? paymentIntentId : null,
      status: paymentMethod === 'cod' ? 'pending' : 'paid',
      deliveryStatus: 'pending',
      items,
    });

    await newOrder.save();

    // Clear the user's cart
    await CartItem.deleteMany({ userId });

    // Return the order ID and order details
    return res.json({ message: 'Order placed successfully', orderId: newOrder._id, order: newOrder });
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
// Route to update the adress 

app.post('/api/users/:userId/addresses', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const { fullName, phoneNumber, pinCode, locality, address, city, state, landmark } = req.body;

    if (req.user.userId !== userId) {
      return res.status(403).json({ message: 'Unauthorized access' });
    }

    const newAddress = new Address({
      userId,
      fullName,
      phoneNumber,
      pinCode,
      locality,
      address,
      city,
      state,
      landmark,
    });

    const orderID = crypto.randomBytes(16).toString('hex'); // Generate a unique order ID
    const hmac = crypto.createHmac('sha256', process.env.SECRET_KEY || 'your_secret_key');
    hmac.update(orderID);
    const hashedOrderID = hmac.digest('hex');

    const newOrder = new Order({
      orderId: hashedOrderID,
      paymentMethod: 'cod',
      userId: req.user._id,
      // Add other required fields here
    });

    await newOrder.save();

    await newAddress.save();

    res.status(201).json({ message: 'Order placed successfully', orderId: newOrder._id });
  } catch (error) {

    console.error('Error saving address:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


// ============================================================comments
// route to post the comments
app.post('/api/comments', authenticateToken, async (req, res) => {
  try {
    const { productId, text, rating } = req.body;
    const userId = req.user.userId;

    console.log('Received comment data:', { productId, text, rating });
    console.log('User ID:', userId);

    const existingComment = await Comment.findOne({ product: productId, 'buyerId._id': userId });
    if (existingComment) {
      return res.status(400).json({ message: 'You have already commented on this product.' });
    }

    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    console.log('User object:', user);

 
    const userName = user.name || user.username || user.email.split('@')[0] || 'Anonymous';

const newComment = new Comment({
  text,
  author: {
    _id: user._id,
    name: userName
  },
  seller: product.seller,
  buyerId: {
    _id: user._id,
    name: userName
  },
  product: productId,
  rating,
});


    console.log('New comment before save:', newComment); // Log the comment before saving

    await newComment.save();

    console.log('New comment saved:', newComment);

    res.status(201).json(newComment);
  } catch (error) {
    console.error('Error creating comment:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ message: 'Internal server error', error: error.message, stack: error.stack });
  }
});
// Route to fetch comments for a specific product
app.get('/api/products/:productId/comments', async (req, res) => {
  try {
    const { productId } = req.params;

    const comments = await Comment.find({ product: productId })
      .sort({ createdAt: -1 });

    res.json(comments);
  } catch (error) {
    console.error('Error fetching comments:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});



// Route to fetch update comments '
app.put('/api/comments/:commentId', authenticateToken, async (req, res) => {
  try {
    const { commentId } = req.params;
    const { rating, text } = req.body;
    const userId = req.user.userId;

    console.log('Updating comment:', { commentId, userId, rating, text });

    const comment = await Comment.findById(commentId);

    if (!comment) {
      console.log('Comment not found:', commentId);
      return res.status(404).json({ message: 'Comment not found' });
    }

    console.log('Found comment:', comment);
    console.log('Comment author:', comment.author);
    console.log('User ID:', userId);

    // Convert both IDs to strings for comparison
    if (comment.author._id.toString() !== userId.toString()) {
      console.log('Authorization failed');
      return res.status(403).json({ message: 'You are not authorized to update this comment' });
    }

    comment.rating = rating;
    comment.text = text;

    await comment.save();

    console.log('Comment updated successfully');
    res.json(comment);
  } catch (error) {
    console.error('Error updating comment:', error);
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

// route to fetch buyer comments in amdin page
app.get('/api/admin/:userType/:userId/comments', authenticateToken, async (req, res) => {
  try {
    const { userId, userType } = req.params;
    console.log(`Fetching ${userType} comments for user ${userId}`);

    let query;
    if (userType === 'buyer') {
      query = { buyerId: userId };
    } else if (userType === 'seller') {
      query = { sellerId: userId };
    } else {
      console.log(`Invalid user type: ${userType}`);
      return res.status(400).json({ message: 'Invalid user type' });
    }

    console.log('Query:', query);

    const comments = await Comment.find(query)
      .populate('buyerId', 'buyerFields.name')
      .populate('sellerId', 'sellerFields.name')
      .sort({ createdAt: -1 });

    console.log(`Found ${comments.length} comments`);

    res.json(comments);
  } catch (error) {
    console.error('Error fetching user comments:', error);
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});
// Route for toggling the active state of a comment
app.put('/api/comments/:commentId/toggle', authenticateToken, async (req, res) => {
  try {
    const { commentId } = req.params;
    const { isActive } = req.body;

    // Check if the user is authorized to toggle the review (e.g., is an admin or a seller)
    if (req.user.userType !== 'admin' && req.user.userType !== 'seller') {
      return res.status(403).json({ message: 'Unauthorized access' });
    }

    const updatedComment = await Comment.findByIdAndUpdate(
      commentId,
      { isActive },
      { new: true }
    );

    if (!updatedComment) {
      return res.status(404).json({ message: 'Comment not found' });
    }

    res.json(updatedComment);
  } catch (error) {
    console.error('Error toggling review:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
// Route to fetch seller comments
app.get('/api/seller/comments', authenticateToken, async (req, res) => {
  try {
    const sellerId = req.user.userId;
    console.log('Seller ID:', sellerId);

    const comments = await Comment.find()
      .populate('author', 'name')
      .populate({
        path: 'product',
        match: { seller: sellerId },
        select: 'name'
      })
      .populate('buyerId', 'name');

    const sellerComments = comments.filter(comment => comment.product !== null);

    console.log('Total comments found:', comments.length);
    console.log('Seller comments after filtering:', sellerComments.length);

    res.json(sellerComments);
  } catch (error) {
    console.error('Error fetching seller comments:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Route to like or dislike the comments 

app.post('/api/comments/:commentId/react', authenticateToken, async (req, res) => {
  try {
    const { commentId } = req.params;
    const { action } = req.body;
    const userId = req.user.userId;
    const userType = req.user.userType;

    console.log(`Reacting to comment: ${commentId}, Action: ${action}, User ID: ${userId}, User Type: ${userType}`);

    if (!userId) {
      console.log('User ID is undefined. Token may be invalid or expired.');
      return res.status(401).json({ message: 'Unauthorized: Invalid or expired token' });
    }

    // Fetch the comment
    const comment = await Comment.findById(commentId);
    if (!comment) {
      console.log(`Comment not found: ${commentId}`);
      return res.status(404).json({ message: 'Comment not found' });
    }

    // Fetch the user's name if needed
    const user = await User.findById(userId);
    const userName = user ? user.name : 'Unknown User';

    // Initialize arrays if they don't exist
    comment.likedBy = comment.likedBy || [];
    comment.dislikedBy = comment.dislikedBy || [];

    // Remove any existing reaction from this user
    comment.likedBy = comment.likedBy.filter(user => user && user._id && user._id.toString() !== userId);
    comment.dislikedBy = comment.dislikedBy.filter(user => user && user._id && user._id.toString() !== userId);

    // Add the new reaction
    if (action === 'like') {
      comment.likedBy.push({ _id: userId, name: userName });
    } else if (action === 'dislike') {
      comment.dislikedBy.push({ _id: userId, name: userName });
    }

    // Update counts
    comment.likeCount = comment.likedBy.length;
    comment.dislikeCount = comment.dislikedBy.length;

    await comment.save();

    // Fetch the product
    const product = await Product.findById(comment.productId);

    // Fetch total unique reactions for this product
    const allComments = await Comment.find({ productId: comment.productId });
    const uniqueReactors = new Set();
    allComments.forEach(comm => {
      (comm.likedBy || []).forEach(liker => liker && liker._id && uniqueReactors.add(liker._id.toString()));
      (comm.dislikedBy || []).forEach(disliker => disliker && disliker._id && uniqueReactors.add(disliker._id.toString()));
    });

    const totalUniqueReactions = uniqueReactors.size;

    res.json({
      commentId: comment._id,
      likeCount: comment.likeCount,
      dislikeCount: comment.dislikeCount,
      isLiked: action === 'like',
      isDisliked: action === 'dislike',
      totalUniqueReactions,
      productName: product ? product.name : 'Unknown Product'
    });
  } catch (error) {
    console.error('Server error when reacting to comment:', error);
    res.status(500).json({ message: 'An error occurred while reacting to the comment', error: error.message });
  }
});

// ============================admin reports ==============================
// Route to fetch total number of registered users
app.get("/api/admin/reports/users", authenticateToken, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    res.json({ count: totalUsers });
  } catch (error) {
    console.error("Error fetching total users:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Route to fetch total number of sellers
app.get("/api/admin/reports/sellers", authenticateToken, async (req, res) => {
  try {
    const sellers = await User.countDocuments({ userType: "seller" });
    res.json({ count: sellers });
  } catch (error) {
    console.error("Error fetching sellers:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Route to fetch total number of buyer products
app.get("/api/admin/reports/buyer-products", authenticateToken, async (req, res) => {
  try {
    const buyerProducts = await Product.countDocuments();
    res.json({ count: buyerProducts });
  } catch (error) {
    console.error("Error fetching buyer products:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Route to fetch total number of delivered products
app.get("/api/admin/reports/delivered-products", authenticateToken, async (req, res) => {
  try {
    const deliveredProducts = await Order.countDocuments({ deliveryStatus: "delivered" });
    res.json({ count: deliveredProducts });
  } catch (error) {
    console.error("Error fetching delivered products:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Route to fetch number of users registered in the last 30 days
app.get("/api/admin/reports/users-last-30-days", authenticateToken, async (req, res) => {
  try {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const usersLast30Days = await User.countDocuments({ createdAt: { $gte: thirtyDaysAgo } });
    res.json({ count: usersLast30Days });
  } catch (error) {
    console.error("Error fetching users registered in last 30 days:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Route to fetch number of sellers registered in the last 30 days
app.get("/api/admin/reports/sellers-last-30-days", authenticateToken, async (req, res) => {
  try {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const sellersLast30Days = await User.countDocuments({
      createdAt: { $gte: thirtyDaysAgo },
      userType: "seller",
    });
    res.json({ count: sellersLast30Days });
  } catch (error) {
    console.error("Error fetching sellers registered in last 30 days:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Route to fetch number of buyer products added in the last 30 days
app.get("/api/admin/reports/buyer-products-last-30-days", authenticateToken, async (req, res) => {
  try {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const buyerProductsLast30Days = await Product.countDocuments({ createdAt: { $gte: thirtyDaysAgo } });
    res.json({ count: buyerProductsLast30Days });
  } catch (error) {
    console.error("Error fetching buyer products added in last 30 days:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
app.get("/", async(req , res)=>{
   res.send("Server is running Let's Go============>>>>>>>>>>>>")
})
// Route to fetch number of products delivered in the last 30 days
app.get("/api/admin/reports/delivered-products-last-30-days", authenticateToken, async (req, res) => {
  try {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const deliveredProductsLast30Days = await Order.countDocuments({
      createdAt: { $gte: thirtyDaysAgo },
      deliveryStatus: "delivered",
    });
    res.json({ count: deliveredProductsLast30Days });
  } catch (error) {
    console.error("Error fetching products delivered in last 30 days:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});


  const PORT = 5002;
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });  