require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const morgan = require("morgan");
const speakeasy = require("speakeasy");
const nodemailer = require("nodemailer");
const tf = require("@tensorflow/tfjs-node");
const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

// 🔹 Connect to MongoDB
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
  console.error("❌ MONGO_URI is missing in .env file");
  process.exit(1);
}

mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected Successfully"))
  .catch((err) => console.error("❌ MongoDB Connection Failed:", err));

// 🔹 User Schema & Model
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

// 🔹 Product Schema & Model
const ProductSchema = new mongoose.Schema({
  name: String,
  category: String,
  sustainability_score: Number,
  price: { type: Number, required: true },
  currency: { type: String, default: "INR" }
});
const Product = mongoose.model("Product", ProductSchema);

// 🔹 Cart Schema & Model
const CartSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
  quantity: { type: Number, default: 1 }, 
  addedAt: { type: Date, default: Date.now }
});
const Cart = mongoose.model("Cart", CartSchema);

// 🔹 Machine Learning-based Recommendation System
app.get("/api/products/recommend/:userId", async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    const allProducts = await Product.find();
    if (allProducts.length === 0) return res.json([]);

    const userPreferences = user.preferences;
    const likedProducts = user.likedProducts.map(id => id.toString());
    const dislikedProducts = user.dislikedProducts.map(id => id.toString());

    const scores = allProducts.map(product => {
      let score = product.sustainability_score;
      if (userPreferences.includes(product.category)) score += 2;
      if (likedProducts.includes(product._id.toString())) score += 3;
      if (dislikedProducts.includes(product._id.toString())) score -= 3;
      return { product, score };
    });

    scores.sort((a, b) => b.score - a.score);
    const recommendedProducts = scores.slice(0, 10).map(item => item.product);

    res.json(recommendedProducts);
  } catch (error) {
    console.error("Error fetching recommendations:", error);
    res.status(500).json({ message: "Error fetching recommendations", error });
  }
});

// 🔹 Register User
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

// 🔹 Root Route
app.get("/", (req, res) => res.send("🌱 Sustainable Product Recommender API Running 🚀"));

// 🔹 Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
