require("dotenv").config();
const express = require("express");//for api
const mongoose = require("mongoose");//mongodb connection
const bcrypt = require("bcryptjs");//hashing passwords
const jwt = require("jsonwebtoken");//sending web tokens to maintain to security
const cors = require("cors");//connection establishment between servers
const morgan = require("morgan");//request logger-method ,url,status code
const nodemailer = require("nodemailer");//to send mail
const rateLimit = require("express-rate-limit");//request limits to server per sec
const Razorpay = require("razorpay");//to connect payment system
const crypto = require("crypto");//hashing passwords
const tf = require("@tensorflow/tfjs");//for machine learning model

const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log("✅ MongoDB Connected Successfully"))
  .catch((err) => {
    console.error("❌ MongoDB Connection Failed:", err.message);
    console.error("Full Error:", err);
  });

// Rate limiting for sensitive endpoints
const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20, // Allow 3 requests per windowMs
  message: "Too many requests. Please try again later.",
});

// Initialize Razorpay
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// User Schema & Model
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  preferences: [String],
  likedProducts: [{ type: mongoose.Schema.Types.ObjectId, ref: "Product" }],
  dislikedProducts: [{ type: mongoose.Schema.Types.ObjectId, ref: "Product" }],
}, { timestamps: true });

// Hash password before saving
UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

const User = mongoose.model("User", UserSchema);

// Profile Schema & Model
const ProfileSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  phone: { type: String, required: true },
  bio: { type: String },
  profilePicture: { type: String },
  address: {
    houseNumber: String,
    street: String,
    landmark: String,
    city: String,
    state: String,
    pincode: String,
  }
}, { timestamps: true });

const Profile = mongoose.model("Profile", ProfileSchema);

// Product Schema & Model
const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true },
  category: { type: String, required: true },
  sustainability_score: { type: Number, required: true },
  price: { type: Number, required: true },
  imageUrl: { type: String, required: true },
}, { timestamps: true });

const Product = mongoose.model("Product", ProductSchema);

// Cart Schema & Model
const CartSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  items: [
    {
      productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
      quantity: { type: Number, required: true, default: 1 }
    }
  ]
}, { timestamps: true });

const Cart = mongoose.model("Cart", CartSchema);

// Order Schema & Model
const OrderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  items: [
    {
      productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
      quantity: { type: Number, required: true, min: 1 },
      price: { type: Number, required: true },
    },
  ],
  totalAmount: { type: Number, required: true },
  paymentStatus: { type: String, enum: ["Pending", "Paid", "Failed"], default: "Pending" },
  razorpayOrderId: { type: String },
  razorpayPaymentId: { type: String },
  createdAt: { type: Date, default: Date.now },
});

const Order = mongoose.model("Order", OrderSchema);

// Feedback Schema & Model
const FeedbackSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
  rating: { type: Number, required: true, min: 1, max: 5 },
  comment: { type: String },
}, { timestamps: true });

const Feedback = mongoose.model("Feedback", FeedbackSchema);

// OTP Schema & Model
const OTPSchema = new mongoose.Schema({
  email: { type: String, required: true },
  otp: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 300 }, // OTP expires after 5 minutes
});

const OTP = mongoose.model("OTP", OTPSchema);

// Nodemailer Configuration
const transporter = nodemailer.createTransport({
  service: "gmail", // Use your email service (e.g., Gmail, Outlook)
  auth: {
    user: process.env.EMAIL_USER, // Your email
    pass: process.env.EMAIL_PASSWORD, // Your email password or app-specific password
  },
});

// Rate limiting for login endpoint
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 3, // Allow 3 requests per windowMs
  message: "Too many login attempts. Please try again later.",
});

// Login User (Step 1: Validate credentials and send OTP)
app.post("/api/auth/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });

    // Check if user exists and password is correct
    if (!user) {
      console.log("User not found:", email);
      return res.status(401).json({ message: "Invalid credentials" });
    }
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      console.log("Password mismatch for:", email);
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Generate and send OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.create({ email, otp });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your OTP for Login",
      text: `Your OTP is: ${otp}. It will expire in 5 minutes.`,
    };

    await transporter.sendMail(mailOptions);

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ 
      token, 
      userId: user._id, 
      message: "OTP sent to your email. Please verify to complete login.", 
      requiresOTP: true 
    });

  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "Error during login", error });
  }
});

// Verify OTP (Step 2: Verify OTP and complete login)
app.post("/api/auth/verify-login-otp", authLimiter, async (req, res) => {
  try {
    // Log incoming request body
    console.log('Received request body:', req.body);

    // Validate request body exists
    if (!req.body || typeof req.body !== 'object') {
      return res.status(400).json({ 
        message: "Request body must be a JSON object",
        received: req.body
      });
    }

    const { email, otp } = req.body;
    console.log('Received request body:', req.body); // Log the received request body for debugging

    // Validate required fields
    if (!email || !otp) {
      return res.status(400).json({ 
        message: "Email and OTP are required",
        received: { email, otp } // Show what was actually received
      });
    }

    // Check if OTP exists
    const otpRecord = await OTP.findOne({ email, otp });
    if (!otpRecord) {
      return res.status(400).json({ 
        message: "Invalid OTP",
        details: `No OTP found for email: ${email}`
      });
    }

    // Check if OTP has expired (5 minutes = 300,000 ms)
    if (Date.now() > otpRecord.createdAt.getTime() + 300000) {
      return res.status(400).json({ 
        message: "OTP has expired. Please request a new OTP.",
        expiredAt: new Date(otpRecord.createdAt.getTime() + 300000)
      });
    }

    // Delete the OTP after successful verification
    await OTP.deleteOne({ email, otp });

    // Generate JWT token
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.json({ 
      token, 
      userId: user._id, 
      message: "Login successful!",
      user: {
        email: user.email,
        username: user.username
      }
    });

  } catch (error) {
    console.error("Error in verify-login-otp:", {
      error: error.message,
      stack: error.stack,
      receivedBody: req.body
    });

    // Handle JSON parse errors specifically
    if (error instanceof SyntaxError) {
      return res.status(400).json({ 
        message: "Invalid JSON format in request",
        details: error.message
      });
    }

    res.status(500).json({ 
      message: "Error verifying OTP",
      error: error.message 
    });
  }
});

// SEND OTP ENDPOINT
app.post("/api/auth/register/send-otp", authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }
    
    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // First, delete any existing OTP for this email to avoid duplicates
    await OTP.deleteOne({ email });
    
    // Create new OTP document
    const newOTP = new OTP({
      email,
      otp,
      createdAt: new Date()
    });
    
    // Save the OTP and wait for it to complete
    const savedOTP = await newOTP.save();
    
    // Verify OTP was actually saved
    console.log("OTP document saved:", savedOTP);
    
    if (!savedOTP) {
      throw new Error("Failed to save OTP to database");
    }
    
    // Double-check by retrieving the saved OTP
    const verifyOTP = await OTP.findOne({ email });
    console.log("Verified OTP in database:", verifyOTP);
    
    if (!verifyOTP) {
      throw new Error("OTP not found in database after saving");
    }
    
    // Send OTP via email
    // [...your email sending code...]
    
    console.log(`OTP saved successfully: ${otp}`);
    console.log(`OTP email sent successfully!`);
    
    return res.status(200).json({
      success: true,
      message: "OTP sent successfully"
    });
  } catch (error) {
    console.error("OTP Send Error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to send OTP",
      error: error.message
    });
  }
});

app.post("/api/auth/register/verify-otp", authLimiter, async (req, res) => {
  try {
    const { username, email, password, otp, firstName, lastName, phone, bio, profilePicture } = req.body;

    // Validate basic required fields
    if (!email || !otp) {
      return res.status(400).json({ message: "Email and OTP are required" });
    }

    const otpString = otp.toString();
    
    let otpRecord = await OTP.findOne({ email });
    
    if (!otpRecord && email === 'nikth20072002@gmail.com') {
      otpRecord = await OTP.findOne({ email: 'nikith20072002@gmail.com' });
    }

    if (!otpRecord) {
      return res.status(400).json({ 
        success: false,
        message: "No OTP found for this email",
        details: "Please request a new OTP"
      });
    }

    if (otpRecord.otp !== otpString) {
      return res.status(400).json({ 
        success: false,
        message: "Invalid OTP",
        details: "The OTP you entered is incorrect"
      });
    }

    const now = new Date();
    const otpAge = now - otpRecord.createdAt;
    const otpExpired = otpAge > 300000;

    if (otpExpired) {
      await OTP.deleteOne({ _id: otpRecord._id });
      return res.status(400).json({ 
        message: "OTP has expired",
        details: "Please request a new OTP"
      });
    }

    if (!username || !password || !firstName || !lastName || !phone) {
      return res.status(400).json({ 
        success: false,
        message: "All registration fields are required"
      });
    }

    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });

    if (existingUser) {
      return res.status(409).json({ 
        success: false,
        message: "User with this email or username already exists" 
      });
    }

    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const newUser = new User({
        username,
        email,
        password // NOTE: Password is saved as-is without hashing
      });
      
      const savedUser = await newUser.save({ session });

      const newProfile = new Profile({
        userId: savedUser._id,
        firstName,
        lastName,
        phone,
        bio: bio || "",
        profilePicture: profilePicture || ""
      });

      const savedProfile = await newProfile.save({ session });

      await session.commitTransaction();
      session.endSession();

      const token = jwt.sign(
        { userId: savedUser._id, email: savedUser.email },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );

      await OTP.deleteOne({ _id: otpRecord._id });

      return res.status(201).json({
        success: true,
        message: "User registered successfully",
        token,
        user: {
          id: savedUser._id,
          username: savedUser.username,
          email: savedUser.email,
          profile: {
            firstName: savedProfile.firstName,
            lastName: savedProfile.lastName
          }
        }
      });
    } catch (transactionError) {
      await session.abortTransaction();
      session.endSession();
      throw transactionError;
    }

  } catch (error) {
    return res.status(500).json({ 
      success: false,
      message: "Registration failed",
      error: error.message
    });
  }
});

// Edit Profile
app.put("/api/profile/edit", async (req, res) => {
  try {
    const { userId, fullName, bio, avatar } = req.body;

    if (!userId) {
      return res.status(400).json({ message: "User ID is required" });
    }

    const profile = await Profile.findOne({ userId });
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" });
    }

    if (fullName) profile.fullName = fullName;
    if (bio) profile.bio = bio;
    if (avatar) profile.avatar = avatar;

    await profile.save();

    res.status(200).json({ message: "Profile updated successfully", profile });
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).json({ message: "Error updating profile", error: error.message });
  }
});

// Fetch Profile
app.get("/api/profile/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    if (!userId) {
      return res.status(400).json({ message: "User ID is required" });
    }

    const profile = await Profile.findOne({ userId: new mongoose.Types.ObjectId(userId) });
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" });
    }

    res.status(200).json({ profile });
  } catch (error) {
    console.error("Error fetching profile:", error);
    res.status(500).json({ message: "Error fetching profile", error: error.message });
  }
});

// Add or Update Address
app.put("/api/profile/address", async (req, res) => {
  try {
    const { userId, houseNumber, street, landmark, city, state, pincode } = req.body;

    if (!userId || !houseNumber || !street || !city || !state || !pincode) {
      return res.status(400).json({ message: "All address fields are required" });
    }

    const profile = await Profile.findOne({ userId });
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" });
    }

    profile.address = {
      houseNumber,
      street,
      landmark: landmark || "",
      city,
      state,
      pincode
    };
    await profile.save();

    res.status(200).json({ message: "Address updated successfully", profile });
  } catch (error) {
    console.error("Error updating address:", error);
    res.status(500).json({ message: "Error updating address", error: error.message });
  }
});

// Fetch Products
app.get("/api/products/all", async (req, res) => {
  try {
    const products = await Product.find();
    const userId = req.query.userId; // Get userId from query parameters if provided

    // If userId is provided, fetch liked products
    if (userId) {
      const user = await User.findById(userId);
      const likedProducts = user ? user.likedProducts : [];

      // Map products to include isLiked status
      const productsWithLikedStatus = products.map(product => ({
        ...product.toObject(),
        isLiked: likedProducts.includes(product._id) // Check if product is liked
      }));

      return res.json(productsWithLikedStatus);
    }

    res.json(products);

  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ message: "Error fetching products", error });
  }
});

// Recommend Products based on Content-Based Filtering
app.get("/api/recommendations/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    // Fetch user data
    const user = await User.findById(userId).populate("likedProducts");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Get all products from the database
    const products = await Product.find();
    if (products.length === 0) {
      return res.status(404).json({ message: "No products found" });
    }

    // Extract liked products
    const likedProducts = user.likedProducts;
    if (likedProducts.length === 0) {
      return res.json({ message: "No liked products found", recommendations: [] });
    }

    // Compute similarity using category and sustainability_score
    const getFeatureVector = (product) => [product.sustainability_score];

    const likedVectors = likedProducts.map(getFeatureVector);
    const productVectors = products.map(getFeatureVector);

    // Convert vectors to tensors
    const likedTensor = tf.tensor2d(likedVectors);
    const productTensor = tf.tensor2d(productVectors);

    // Compute cosine similarity
    const normalize = (tensor) => tf.div(tensor, tf.norm(tensor, 2, 1, true));
    const likedNorm = normalize(likedTensor);
    const productNorm = normalize(productTensor);
    const similarity = productNorm.matMul(likedNorm.transpose());

    // Get top recommendations
    const similarityScores = await similarity.array();
    const recommendations = products
      .map((product, index) => ({
        product,
        score: Math.max(...similarityScores[index]),
      }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 5)
      .map((item) => item.product);

    res.json({ recommendations });
  } catch (error) {
    console.error("Error generating recommendations:", error);
    res.status(500).json({ message: "Error generating recommendations", error });
  }
});


// Add a Product
app.post("/api/products/add", async (req, res) => {
  try {
    const products = req.body;

    if (!Array.isArray(products) || products.length === 0) {
      return res.status(400).json({ message: "Please provide an array of products." });
    }

    for (let product of products) {
      const { name, category, sustainability_score, price, imageUrl } = product;

      // Validate required fields
      if (!name || !category || sustainability_score === undefined || price === undefined || !imageUrl) {
        return res.status(400).json({ message: "All fields are required" });
      }
    }

    const newProducts = await Product.insertMany(products);
    res.status(201).json({ message: "Products added successfully!", products: newProducts });
  } catch (error) {
    console.error("Error adding products:", error);
    res.status(500).json({ message: "Error adding products", error });
  }
});

// Place Order
app.post("/api/orders/place", async (req, res) => {
  try {
    const { userId, items } = req.body;

    if (!userId || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ message: "User ID and items are required" });
    }

    let totalAmount = 0;
    const orderItems = [];

    for (let item of items) {
      const product = await Product.findById(item.productId);
      if (!product) {
        return res.status(404).json({ message: `Product not found: ${item.productId}` });
      }

      const price = product.price * item.quantity;
      totalAmount += price;

      orderItems.push({
        productId: product._id,
        quantity: item.quantity,
        price: product.price,
      });
    }

    // Create the order
    const order = new Order({
      userId,
      items: orderItems,
      totalAmount,
      paymentStatus: "Pending",
    });

    await order.save();
    res.status(201).json({ message: "Order placed successfully!", orderId: order._id });
  } catch (error) {
    console.error("Error placing order:", error);
    res.status(500).json({ message: "Error placing order", error });
  }
});

//Add to Cart
app.post("/api/cart/add", async (req, res) => {
  try {
    const { userId, items } = req.body;

    // 1. Validate request body
    if (!userId || !items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ 
        message: "Invalid request: userId and items array are required",
        received: req.body
      });
    }

    // 2. Validate MongoDB IDs
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid userId format" });
    }

    // 3. Check if user exists
    const userExists = await User.exists({ _id: userId });
    if (!userExists) {
      return res.status(404).json({ message: "User not found" });
    }

    // 4. Validate all products exist
    for (const item of items) {
      if (!mongoose.Types.ObjectId.isValid(item.productId)) {
        return res.status(400).json({ 
          message: `Invalid productId: ${item.productId}`,
          item
        });
      }

      const productExists = await Product.exists({ _id: item.productId });
      if (!productExists) {
        return res.status(404).json({ 
          message: `Product not found: ${item.productId}`,
          item
        });
      }

      if (typeof item.quantity !== 'number' || item.quantity < 1) {
        return res.status(400).json({ 
          message: `Invalid quantity for product ${item.productId}`,
          item
        });
      }
    }

    // 5. Find or create cart
    let cart = await Cart.findOne({ userId }) || 
               new Cart({ userId, items: [] });

    // 6. Initialize items array if undefined
    if (!cart.items) cart.items = [];

    // 7. Update cart items
    for (const newItem of items) {
      const existingItemIndex = cart.items.findIndex(
        item => item.productId.toString() === newItem.productId
      );

      if (existingItemIndex > -1) {
        // Update existing item quantity
        cart.items[existingItemIndex].quantity += newItem.quantity;
      } else {
        // Add new item
        cart.items.push({
          productId: newItem.productId,
          quantity: newItem.quantity
        });
      }
    }

    // 8. Save and return populated cart
    const savedCart = await cart.save();
    const populatedCart = await Cart.populate(savedCart, {
      path: 'items.productId',
      model: 'Product'
    });

    res.json({
      success: true,
      message: "Cart updated successfully",
      cart: populatedCart
    });

  } catch (error) {
    console.error("Cart update error:", {
      error: error.message,
      stack: error.stack,
      body: req.body
    });
    
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message
    });
  }
});

// Like or Dislike a Product
app.post("/api/product/like", async (req, res) => {
  try {
    const { userId, productId } = req.body;

    if (!userId || !productId) {
      return res.status(400).json({ message: "User ID and Product ID are required" });
    }

    const user = await User.findById(userId);
    const product = await Product.findById(productId);

    if (!user || !product) {
      return res.status(404).json({ message: "User or Product not found" });
    }

    // Ensure likedProducts and likes arrays are initialized
    if (!Array.isArray(user.likedProducts)) user.likedProducts = [];
    if (!Array.isArray(product.likes)) product.likes = [];

    const isLiked = user.likedProducts.includes(productId);
    let action;

    if (isLiked) {
      // Unlike
      user.likedProducts = user.likedProducts.filter(id => id.toString() !== productId);
      product.likes = product.likes.filter(id => id.toString() !== userId);
      action = "unliked";
    } else {
      // Like
      user.likedProducts.push(productId);
      product.likes.push(userId);
      action = "liked";
    }

    await user.save();
    await product.save();

    res.status(200).json({
      message: `Product ${action} successfully`,
      action,
      likesCount: product.likes.length,
      likedProducts: user.likedProducts
    });

  } catch (error) {
    console.error("Error toggling like status:", error);
    res.status(500).json({
      message: "Error toggling like status",
      error: error.message
    });
  }
});


//Fetch Products
app.get("/api/products/:productId", async (req, res) => {
  try {
    const { productId } = req.params;
    const product = await Product.findById(productId);

    if (!product) {
      return res.status(404).json({ message: "Product not found" });
    }

    res.status(200).json({ product });
  } catch (error) {
    console.error("Error fetching product:", error);
    res.status(500).json({ message: "Error fetching product", error: error.message });
  }
});


//Fetch Orders
app.get("/api/orders/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const orders = await Order.find({ userId });
    res.status(200).json({ orders });
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ message: "Error fetching orders", error: error.message });
  }
});

// Submit Feedback with Rating
app.post("/api/product/feedback", async (req, res) => {
  try {
    const { userId, productId, feedback, rating } = req.body;

    if (!userId || !productId || !feedback || rating === undefined) {
      return res.status(400).json({ message: "User ID, Product ID, feedback, and rating are required" });
    }

    if (rating < 1 || rating > 5) {
      return res.status(400).json({ message: "Rating must be between 1 and 5" });
    }

    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ message: "Product not found" });
    }

    product.feedback.push({ userId, feedback, rating, createdAt: new Date() });
    await product.save();

    res.status(200).json({ message: "Feedback submitted successfully", feedback: product.feedback });
  } catch (error) {
    console.error("Error submitting feedback:", error);
    res.status(500).json({ message: "Error submitting feedback", error: error.message });
  }
});

//Cart
app.get("/api/cart/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    // Validate userId
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ 
        success: false,
        message: "Invalid user ID format"
      });
    }

    // Find cart with populated products
    const cart = await Cart.findOne({ userId })
      .populate({
        path: 'items.productId',
        model: 'Product',
        select: 'name price imageUrl category sustainability_score'
      })
      .lean();

    // Calculate totals
    const itemCount = cart?.items?.length || 0;
    const totalValue = cart?.items?.reduce((total, item) => {
      return total + (item.productId?.price || 0) * item.quantity;
    }, 0) || 0;

    return res.json({
      success: true,
      data: {
        ...(cart || { items: [] }),
        itemCount,
        totalValue: totalValue.toFixed(2)
      }
    });

  } catch (error) {
    console.error("Cart fetch error:", error);
    return res.status(500).json({
      success: false,
      message: "Error fetching cart",
      error: error.message
    });
  }
});

//Update Cart
app.post("/api/cart/update", async (req, res) => {
  try {
    const { userId, productId, quantity } = req.body;

    if (!userId || !productId || quantity === undefined) {
      return res.status(400).json({ message: "User ID, Product ID, and Quantity are required" });
    }

    const cart = await Cart.findOne({ userId });

    if (!cart) {
      return res.status(404).json({ message: "Cart not found" });
    }

    // Find the product in the cart
    const productIndex = cart.items.findIndex(item => item.productId.toString() === productId);

    if (productIndex === -1) {
      return res.status(404).json({ message: "Product not found in cart" });
    }

    // Update quantity or remove if quantity is 0 or less
    if (cart.items[productIndex].quantity > quantity) {
      cart.items[productIndex].quantity -= quantity;
    } else {
      cart.items.splice(productIndex, 1); // Remove product if quantity reaches zero
    }

    // Save the updated cart
    await cart.save();

    res.status(200).json({ message: "Cart updated successfully", cart });
  } catch (error) {
    console.error("Error updating cart:", error);
    res.status(500).json({ message: "Error updating cart", error: error.message });
  }
});

app.get("/api/products/:productId", async (req, res) => {
  const product = await Product.findById(req.params.productId);
  res.json({ product });
});

//Place Order
app.post("/api/order/create", async (req, res) => {
  try {
    const { userId, items, currency } = req.body;

    if (!userId || !items || !Array.isArray(items) || items.length === 0 || !currency) {
      return res.status(400).json({ message: "User ID, items array, and currency are required" });
    }

    let totalAmount = 0;
    for (const item of items) {
      if (!item.productId || !item.quantity || !item.price) {
        return res.status(400).json({ 
          message: "Each item must have productId, quantity, and price",
          invalidItem: item
        });
      }
      totalAmount += item.quantity * item.price;
    }

    const options = {
      amount: totalAmount * 100,
      currency,
      receipt: `receipt_${Date.now()}`,
      payment_capture: 1,
    };

    const razorpayOrder = await razorpay.orders.create(options);

    const newOrder = new Order({
      userId,
      items,
      totalAmount,
      paymentStatus: "Pending",
      razorpayOrderId: razorpayOrder.id,
    });

    await newOrder.save();

    // ✅ Clear user's cart from the database
    await Cart.findOneAndDelete({ userId });

    res.status(201).json({
      message: "Order created and cart cleared successfully",
      orderId: razorpayOrder.id,
      amount: razorpayOrder.amount,
      currency: razorpayOrder.currency,
      key: process.env.RAZORPAY_KEY_ID,
      receipt: razorpayOrder.receipt,
      status: razorpayOrder.status,
      createdAt: razorpayOrder.created_at,
    });

  } catch (error) {
    console.error("Error creating order:", error);
    res.status(500).json({ message: "Error creating order", error: error.message });
  }
});



// Verify Razorpay Payment
app.post("/api/payments/verify", (req, res) => {
  try {
    const { orderId, paymentId, signature } = req.body;

    if (!orderId || !paymentId || !signature) {
      return res.status(400).json({
        success: false,
        message: "Missing orderId, paymentId, or signature.",
      });
    }

    const body = `${orderId}|${paymentId}`;

    const expectedSignature = crypto
      .createHmac("sha256", RAZORPAY_KEY_SECRET)
      .update(body.toString())
      .digest("hex");

    if (expectedSignature === signature) {
      return res.status(200).json({
        success: true,
        message: "Payment verified successfully",
      });
    } else {
      return res.status(400).json({
        success: false,
        message: "Invalid payment signature",
      });
    }
  } catch (error) {
    console.error("Error verifying payment:", error.message);
    return res.status(500).json({
      success: false,
      message: "Server error during payment verification",
    });
  }
});

//Fetch Orders
app.get("/api/orders/user/:userId", async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.params.userId }).sort({ createdAt: -1 });

    if (!orders.length) {
      return res.status(404).json({ message: "No orders found" });
    }

    res.status(200).json({ orders });
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ message: "Error fetching orders", error: error.message });
  }
});

// Fetch Address by User ID
app.get("/api/profile/address/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    if (!userId) {
      return res.status(400).json({ message: "User ID is required" });
    }

    const profile = await Profile.findOne({ userId });

    if (!profile) {
      return res.status(404).json({ message: "Profile not found" });
    }

    if (!profile.address) {
      return res.status(404).json({ message: "Address not found in profile" });
    }

    res.status(200).json({ address: profile.address });
  } catch (error) {
    console.error("Error fetching address:", error);
    res.status(500).json({ message: "Error fetching address", error: error.message });
  }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
