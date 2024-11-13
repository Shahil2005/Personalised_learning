const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const path = require("path");

const app = express();

// Middleware setup
app.use(bodyParser.json());
app.use(express.static('public')); // Serve static files from the 'public' folder
app.use(bodyParser.urlencoded({ extended: true }));

// Session management setup
app.use(session({
    secret: 'yourSecretKey', // Secret key for session
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true in production with HTTPS
}));

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/Database', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log("Connected to Database");
}).catch((err) => {
    console.error("Error connecting to MongoDB", err);
});

// User schema and model
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model("User", UserSchema);

// Sign-up route
app.post("/signup", async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).send("All fields are required");
    }

    try {
        // Check if the user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).send("User already exists");
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = new User({
            name,
            email,
            password: hashedPassword
        });

        // Save the user to the database
        await newUser.save();
        console.log("User registered successfully");

        // Redirect to the signup successful page
        return res.redirect('/signup-sucessful.html');
    } catch (err) {
        console.error("Error during signup", err);
        res.status(500).send("Internal Server Error");
    }
});

// Sign-in route
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send("Both email and password are required");
    }

    try {
        // Check if the user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).send("User not found");
        }

        // Compare the provided password with the hashed password in the database
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send("Invalid credentials");
        }

        // Create a session for the logged-in user
        req.session.userId = user._id;
        req.session.email = user.email;

        console.log("User logged in successfully");

        // Redirect to a welcome page or dashboard
        return res.redirect('index.html'); // Create a dashboard page for logged-in users
    } catch (err) {
        console.error("Error during login", err);
        res.status(500).send("Internal Server Error");
    }
});

// Serve the sign-up/sign-in HTML page
app.get("/", (req, res) => {
    res.set({
        "Allow-access-Allow-Origin": '*'
    });
    res.sendFile(path.join(__dirname, 'public', 'sign.html'));
});

// Logout route
app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send("Failed to log out");
        }
        res.redirect('/');
    });
});

// Start server
app.listen(3001, () => {
    console.log("Server is running on http://localhost:3001");
});
