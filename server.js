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

// 🔹 Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log("✅ MongoDB Connected"))
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

// 🔹 Enable 2FA
app.post("/api/auth/enable-2fa", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const secret = speakeasy.generateSecret();
    user.twoFactorSecret = secret.base32;
    user.is2FAEnabled = true;
    await user.save();

    res.json({ secret: secret.otpauth_url, message: "2FA enabled. Scan the QR code in an authenticator app." });
  } catch (error) {
    console.error("Error enabling 2FA:", error);
    res.status(500).json({ message: "Error enabling 2FA", error });
  }
});

// 🔹 Login User with 2FA
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

// 🔹 Get All Products
app.get("/api/products/all", async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ message: "Error fetching products", error });
  }
});

// 🔹 Add a Product
app.post("/api/products/add", async (req, res) => {
  try {
    const { name, category, sustainability_score, price } = req.body;
    if (!name || !category || sustainability_score === undefined || price === undefined) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const newProduct = await Product.create({ name, category, sustainability_score, price });
    res.status(201).json({ message: "Product added successfully!", product: newProduct });

  } catch (error) {
    console.error("Error adding product:", error);
    res.status(500).json({ message: "Error adding product", error });
  }
});

// 🔹 Like a Product & Update Preferences
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

// 🔹 Dislike a Product
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

// 🔹 Get Recommendations
app.get("/api/products/recommend/:userId", async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    const recommendedProducts = await Product.find({
      category: { $in: user.preferences },
      _id: { $nin: user.dislikedProducts }
    }).limit(10);

    res.json(recommendedProducts);
  } catch (error) {
    console.error("Error fetching recommendations:", error);
    res.status(500).json({ message: "Error fetching recommendations", error });
  }
});

// 🔹 Add to Cart
app.post("/api/cart/add", async (req, res) => {
  try {
    const { userId, productId, quantity = 1 } = req.body;
    if (!userId || !productId) return res.status(400).json({ message: "User ID and Product ID required" });

    const cartItem = await Cart.findOneAndUpdate(
      { userId, productId },
      { $inc: { quantity } },
      { new: true, upsert: true }
    );

    res.json({ message: "Product added to cart!", cartItem });
  } catch (error) {
    console.error("Error adding to cart:", error);
    res.status(500).json({ message: "Error adding to cart", error });
  }
});

// 🔹 Get Cart Items
app.get("/api/cart/:userId", async (req, res) => {
  try {
    const cartItems = await Cart.find({ userId: req.params.userId }).populate("productId");
    res.json(cartItems);
  } catch (error) {
    console.error("Error fetching cart:", error);
    res.status(500).json({ message: "Error fetching cart", error });
  }
});

// 🔹 Remove a Product from Cart
app.delete("/api/cart/remove", async (req, res) => {
  try {
    const { userId, productId } = req.body;
    if (!userId || !productId) return res.status(400).json({ message: "User ID and Product ID required" });

    const deletedItem = await Cart.findOneAndDelete({ userId, productId });

    if (!deletedItem) return res.status(404).json({ message: "Product not found in cart" });

    res.json({ message: "Product removed from cart!", deletedItem });
  } catch (error) {
    console.error("❌ Error removing product from cart:", error);
    res.status(500).json({ message: "Error removing product", error });
  }
});

// 🔹 Clear Entire Cart
app.delete("/api/cart/clear/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    if (!userId) return res.status(400).json({ message: "User ID required" });

    const result = await Cart.deleteMany({ userId });

    if (result.deletedCount === 0) return res.status(404).json({ message: "Cart is already empty" });

    res.json({ message: "Cart cleared successfully!" });
  } catch (error) {
    console.error("❌ Error clearing cart:", error);
    res.status(500).json({ message: "Error clearing cart", error });
  }
});

// 🔹 Root Route
app.get("/", (req, res) => res.send("🌱 Sustainable Product Recommender API Running 🚀"));

// 🔹 Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
