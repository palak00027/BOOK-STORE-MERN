const express = require('express');
const User = require('./user.model');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET_KEY;

// Register new user
router.post("/register", async (req, res) => {
    const { username, password, role } = req.body;
    
    try {
        // Validate input
        if (!username || !password) {
            return res.status(400).send({ message: "Username and password are required!" });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).send({ message: "Username already exists!" });
        }

        // Create new user (password will be hashed by pre-save hook)
        const newUser = new User({
            username,
            password,
            role: role || 'user' // Default to 'user' if no role provided
        });

        await newUser.save();

        // Generate token
        const token = jwt.sign(
            { id: newUser._id, username: newUser.username, role: newUser.role },
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        return res.status(201).json({
            message: "User registered successfully",
            token: token,
            user: {
                username: newUser.username,
                role: newUser.role
            }
        });

    } catch (error) {
        console.error("Failed to register user", error);
        return res.status(500).send({ message: "Failed to register user" });
    }
});

// Login (works for both admin and regular users)
router.post("/login", async (req, res) => {
    const { username, password } = req.body;
    
    try {
        // Validate input
        if (!username || !password) {
            return res.status(400).send({ message: "Username and password are required!" });
        }

        // Find user
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).send({ message: "User not found!" });
        }

        // Compare password using bcrypt
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).send({ message: "Invalid password!" });
        }

        // Generate token
        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        return res.status(200).json({
            message: "Authentication successful",
            token: token,
            user: {
                username: user.username,
                role: user.role
            }
        });

    } catch (error) {
        console.error("Failed to login", error);
        return res.status(500).send({ message: "Failed to login" });
    }
});

// Admin login (kept for backwards compatibility, but uses same logic)
router.post("/admin", async (req, res) => {
    const { username, password } = req.body;
    
    try {
        // Validate input
        if (!username || !password) {
            return res.status(400).send({ message: "Username and password are required!" });
        }

        // Find admin user
        const admin = await User.findOne({ username, role: 'admin' });
        if (!admin) {
            return res.status(404).send({ message: "Admin not found!" });
        }

        // Compare password using bcrypt
        const isPasswordValid = await bcrypt.compare(password, admin.password);
        if (!isPasswordValid) {
            return res.status(401).send({ message: "Invalid password!" });
        }

        // Generate token
        const token = jwt.sign(
            { id: admin._id, username: admin.username, role: admin.role },
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        return res.status(200).json({
            message: "Authentication successful",
            token: token,
            user: {
                username: admin.username,
                role: admin.role
            }
        });

    } catch (error) {
        console.error("Failed to login as admin", error);
        return res.status(500).send({ message: "Failed to login as admin" });
    }
});

module.exports = router;