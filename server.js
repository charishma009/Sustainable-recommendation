require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const morgan = require("morgan");
const speakeasy = require("speakeasy");
const nodemailer = require("nodemailer");
const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Connection Failed:", err));

// User Schema & Model
const UserSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: String,
  preferences: [String], 
  likedProducts: [{ type: mongoose.Schema.Types.ObjectId, ref: "Product" }],
  dislikedProducts: [{ type: mongoose.Schema.Types.ObjectId, ref: "Product" }],
  twoFactorSecret: String,
  is2FAEnabled: { type: Boolean, default: false }
});
const User = mongoose.model("User", UserSchema);

// Product Schema & Model
const ProductSchema = new mongoose.Schema({
  name: String,
  category: String,
  sustainability_score: Number,
  price: { type: Number, required: true },
  currency: { type: String, default: "INR" },
  imageUrl: String
});
const Product = mongoose.model("Product", ProductSchema);

// Cart Schema & Model
const CartSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
  quantity: { type: Number, default: 1 }, 
  addedAt: { type: Date, default: Date.now }
});
const Cart = mongoose.model("Cart", CartSchema);

// Feedback Schema & Model
const FeedbackSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
  rating: { type: Number, min: 1, max: 5, required: true },
  comment: String,
  createdAt: { type: Date, default: Date.now }
});
const Feedback = mongoose.model("Feedback", FeedbackSchema);

// Register User
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: "All fields are required" });

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ username, email, password: hashedPassword });
    
    res.status(201).json({ message: "User registered successfully!" });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ message: "Error registering user", error });
  }
});

// Enable 2FA
app.post("/api/auth/enable-2fa", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const secret = speakeasy.generateSecret();
    user.twoFactorSecret = secret.base32;
    user.is2FAEnabled = true;
    await user.save();

    res.json({ secret: secret.otpauth_url, message: "2FA enabled. Scan QR code in authenticator app." });
  } catch (error) {
    console.error("Error enabling 2FA:", error);
    res.status(500).json({ message: "Error enabling 2FA", error });
  }
});

// Login User with 2FA
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password, token } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (user.is2FAEnabled) {
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: "base32",
        token
      });
      if (!verified) return res.status(403).json({ message: "Invalid 2FA token" });
    }

    const tokenJWT = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ token: tokenJWT, userId: user._id });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ message: "Error logging in", error });
  }
});

// Get All Products
app.get("/api/products/all", async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ message: "Error fetching products", error });
  }
});

// Add a Product
app.post("/api/products/add", async (req, res) => {
  try {
    const { name, category, sustainability_score, price, imageUrl } = req.body;
    if (!name || !category || sustainability_score === undefined || price === undefined || !imageUrl) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const newProduct = await Product.create({ name, category, sustainability_score, price, imageUrl });
    res.status(201).json({ message: "Product added successfully!", product: newProduct });
  } catch (error) {
    console.error("Error adding product:", error);
    res.status(500).json({ message: "Error adding product", error });
  }
});

// Like a Product & Update Preferences
app.post("/api/user/like", async (req, res) => {
  try {
    const { userId, productId } = req.body;
    if (!userId || !productId) return res.status(400).json({ message: "User ID and Product ID required" });

    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ message: "Product not found" });

    await User.findByIdAndUpdate(userId, {
      $addToSet: { likedProducts: productId, preferences: product.category },
      $pull: { dislikedProducts: productId }
    });

    res.json({ message: "Product liked! Preferences updated." });
  } catch (error) {
    console.error("Error liking product:", error);
    res.status(500).json({ message: "Error liking product", error });
  }
});

// Dislike a Product
app.post("/api/user/dislike", async (req, res) => {
  try {
    const { userId, productId } = req.body;
    if (!userId || !productId) return res.status(400).json({ message: "User ID and Product ID required" });

    await User.findByIdAndUpdate(userId, {
      $addToSet: { dislikedProducts: productId },
      $pull: { likedProducts: productId }
    });

    res.json({ message: "Product disliked & removed from recommendations." });
  } catch (error) {
    console.error("Error disliking product:", error);
    res.status(500).json({ message: "Error disliking product", error });
  }
});

// Machine Learning Algorithm for Recommendations
const getRecommendedProducts = async (userId) => {
  const user = await User.findById(userId).populate('likedProducts');
  const allProducts = await Product.find();

  // Create a map of product IDs and their corresponding categories
  const productCategoryMap = {};
  allProducts.forEach(product => {
    productCategoryMap[product._id] = product.category;
  });

  // Calculate similarity scores for each product based on user's liked products
  const productScores = {};
  user.likedProducts.forEach(likedProduct => {
    allProducts.forEach(product => {
      if (!productScores[product._id]) {
        productScores[product._id] = 0;
      }
      if (productCategoryMap[product._id] === product.category) {
        productScores[product._id] += 1;
      }
    });
  });

  // Sort products based on similarity scores and return top recommendations
  const recommendedProductIds = Object.keys(productScores)
    .sort((a, b) => productScores[b] - productScores[a])
    .filter(id => !user.likedProducts.includes(id) && !user.dislikedProducts.includes(id))
    .slice(0, 10);

  const recommendedProducts = await Product.find({ _id: { $in: recommendedProductIds } });
  return recommendedProducts;
};

// Get Recommendations
app.get("/api/products/recommend/:userId", async (req, res) => {
  try {
    const recommendedProducts = await getRecommended
