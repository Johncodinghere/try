require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const path = require('path');



const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + '/public'));
app.use(helmet());
app.use(cors({
    origin: 'https://web-sys.onrender.com', // Allow requests from your frontend's URL
    methods: ['GET', 'POST'], // Allow specific HTTP methods
    credentials: true // Allow cookies and session data
}));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Use the environment variable for MongoDB URI
const mongoUri = process.env.MONGODB_URI || 'mongodb+srv://John:1234567887654321@websys.amwpa.mongodb.net/?retryWrites=true&w=majority&appName=WebSys';

if (!mongoUri) {
    console.error('MONGODB_URI is not defined. Check your .env file.');
    process.exit(1);
}

const client = new MongoClient(mongoUri);
let usersCollection;

async function connectToDatabase() {
    try {
        await client.connect();
        console.log('Connected to Database');
        const database = client.db('test'); // Change to your actual database name
        usersCollection = database.collection('users');
    } catch (err) {
        console.error('Failed to connect to Database', err);
        process.exit(1);
    }
}
connectToDatabase();

// Session Management with MongoDB store
app.use(session({
    secret: process.env.SESSION_SECRET, // Make sure SESSION_SECRET is defined in .env
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: mongoUri }),
    cookie: {
        secure: false, // Set to true if using HTTPS
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 30 * 60 * 1000 // 30 minutes
    }
}));

// Helper Functions
function hashPassword(password) {
    const saltRounds = 10;
    return bcrypt.hashSync(password, saltRounds);
}

function isValidPassword(password) {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=\[\]{};:'",.<>?\\|`~])[A-Za-z\d!@#$%^&*()_\-+=\[\]{};:'",.<>?\\|`~]{8,}$/;
    return passwordRegex.test(password);
}


// Rate Limiting for Login Route
const loginLimiter = rateLimit({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // Limit each IP to 5 requests per window
    message: 'Too many login attempts, please try again after 30 minutes.',
    handler: (req, res, next, options) => {
        res.status(options.statusCode).json({ success: false, message: options.message });
    }
});

// Login Route Implementation
app.post('/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    try {
        // Input validation
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required.' });
        }
        if (!validator.isEmail(email)) {
            return res.status(400).json({ success: false, message: 'Invalid email format.' });
        }

        // Fetch user
        const user = await usersCollection.findOne({ emaildb: email });
        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid email or password.' });
        }

        // Account lockout check
        if (user.accountLockedUntil && user.accountLockedUntil > new Date()) {
            const remainingTime = Math.ceil((user.accountLockedUntil - new Date()) / 60000);
            return res.status(403).json({ success: false, message: `Account is locked. Try again in ${remainingTime} minutes.` });
        }

        // Password verification
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            // Handle failed attempts
            let invalidAttempts = (user.invalidLoginAttempts || 0) + 1;
            let updateFields = { invalidLoginAttempts: invalidAttempts };

            if (invalidAttempts >= 3) {
                // Lock account
                updateFields.accountLockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
                updateFields.invalidLoginAttempts = 0;
                await usersCollection.updateOne({ _id: user._id }, { $set: updateFields });
                return res.status(403).json({ success: false, message: 'Account is locked due to multiple failed login attempts. Please try again after 30 minutes.' });
            } else {
                await usersCollection.updateOne({ _id: user._id }, { $set: updateFields });
                return res.status(400).json({ success: false, message: 'Invalid email or password.' });
            }
        }

        // Successful login: reset invalid attempts and lockout fields
        await usersCollection.updateOne(
            { _id: user._id },
            { $set: { invalidLoginAttempts: 0, accountLockedUntil: null, lastLoginTime: new Date() } }
        );

        // Set session data
        req.session.userId = user._id;
        req.session.email = user.emaildb;
        req.session.role = user.role;
        req.session.studentIDNumber = user.studentIDNumber;

        await new Promise((resolve, reject) => {
            req.session.save((err) => {
                if (err) return reject(err);
                resolve();
            });
        });

        res.json({ success: true, role: user.role, message: 'Login successful!' });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ success: false, message: 'Error during login.' });
    }
});

// Middleware to reset invalid login attempts on page navigation
app.use(async (req, res, next) => {
    if (req.session.userId) {
        try {
            await usersCollection.updateOne(
                { _id: req.session.userId },
                { $set: { invalidLoginAttempts: 0, accountLockedUntil: null } }
            );
        } catch (error) {
            console.error('Error resetting invalid login attempts:', error);
        }
    }
    next();
});

// Sign Up Route
app.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    try {
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required.' });
        }
        if (!isValidPassword(password)) {
            return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one special character, and one number.' });
        }

        const existingUser = await usersCollection.findOne({ emaildb: email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Email already registered.' });
        }

        const hashedPassword = hashPassword(password);
        await usersCollection.insertOne({ emaildb: email, password: hashedPassword });
        
        res.json({ success: true, message: 'Account created successfully!' });
    } catch (error) {
        console.error('Error creating account:', error);
        res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// Middleware for Authentication
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.status(401).json({ success: false, message: 'Unauthorized access.' });
    }
}

// Fetch user details route
app.get('/user-details', isAuthenticated, async (req, res) => {
    try {
    const email = req.session.email;
    if (!email) {
    return res.status(401).json({ success: false, message: 'Unauthorized access.' });
    }
    // Fetch user details from the database
    const user = await usersCollection.findOne(
    { emaildb: email },
    { projection: { emaildb: 1 } }
    );
    if (!user) {
    return res.status(404).json({ success: false, message: 'User not found.' });
    }
    // Return only necessary details
    res.json({
    success: true,
    user: {
    email: user.emaildb
    }
    });
    } catch (error) {
    console.error('Error fetching user details:', error);
    res.status(500).json({ success: false, message: 'Error fetching user details.' });
    }
    });
    

// Protected Routes
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/public/dashboard.html');
});

// Logout Route
app.post('/logout', async (req, res) => {
    if (!req.session.userId) {
        return res.status(400).json({ success: false, message: 'No user is logged in.' });
    }
    try {
        req.session.destroy(err => {
            if (err) {
                console.error('Error destroying session:', err);
                return res.status(500).json({ success: false, message: 'Logout failed.' });
            }
            res.clearCookie('connect.sid');
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
            res.setHeader('Surrogate-Control', 'no-store');
            return res.json({ success: true, message: 'Logged out successfully.' });
        });
    } catch (error) {
        console.error('Error during logout:', error);
        return res.status(500).json({ success: false, message: 'Logout failed.' });
    }
});


require('dotenv').config();
const bodyParser = require('body-parser');
const sgMail = require('@sendgrid/mail');
const mongoose = require('mongoose');
const PORT = process.env.PORT || 3000;

function hashPassword(password) {
const saltRounds = 10;
return bcrypt.hashSync(password, saltRounds);
}


// Configure SendGrid API Key
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// MongoDB connection using the URI from .env
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((error) => {
    console.error('MongoDB connection error:', error);
});

// Define Token Schema and Model
const tokenSchema = new mongoose.Schema({
  email: { type: String, required: true },
  token: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 3600 }, // Token expires in 1 hour
});
const Token = mongoose.model('Token', tokenSchema);

// Define User Schema and Model
const userSchema = new mongoose.Schema({
    emaildb: { type: String, required: true },
    password: { type: String, required: true },
    resetKey: String,
    resetExpires: Date,
});

const users = mongoose.model('User', userSchema);


// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public')); // Serve static files from 'public' directory

// Generate Random String Function
function generateRandomString(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const charactersLength = characters.length;
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

// Forgot Password Endpoint
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
  
    if (!email) {
      return res.status(400).json('Email is required');
    }
  
    try {
      // Check if the email exists in MongoDB
      let existingToken = await Token.findOne({ email: email });
      const resetToken = generateRandomString(32);
  
      if (existingToken) {
        // Update the token if the email exists
        existingToken.token = resetToken;
        await existingToken.save();
      } else {
        // Create a new token if the email doesn't exist
        const newToken = new Token({
          email: email,
          token: resetToken,
        });
  
        await newToken.save();
      }
  
      // Send the email with the token (You can call the sendResetCodeEmail here if needed)
      res.status(200).json({ message: 'Password reset token generated and saved' });
    } catch (error) {
      console.error('Error processing forgot-password request:', error);
      res.status(500).json({ message: 'Error processing request' });
    }
  });
  
    // Send the email with the token
    async function sendResetCodeEmail(email, resetCode) {
        const msg = {
          to: email,
          from: 'balicweyjohnwell@gmail.com', // Make sure this email is verified with SendGrid
          subject: 'Your Password Reset Code',
          text: `Your password reset code is: ${resetCode}`,
          html: `<p>Your password reset code is:</p><h3>${resetCode}</h3>`,
        };
      
        try {
          await sgMail.send(msg);
          console.log(`Reset code email sent to ${email}`);
        } catch (error) {
          console.error('Error sending reset code email:', error);
          throw new Error('Error sending reset code email');
        }
      }
      

function generateCode() {
    return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code
  }
  

//send password reset
app.post('/send-password-reset', async (req, res) => {
    const { email } = req.body;
  
    try {
      console.log('Received email:', email);  // Log the received email
      // Ensure you are searching the correct field ('emaildb')
      const user = await users.findOne({ emaildb: email });
      if (!user) {
        console.log('No account found for this email'); 
        return res.status(404).json({ message: 'No account with that email exists' });
      }
      
      const resetCode = generateRandomString(32); 
      
      // Update the user's reset key and expiry time
      user.resetKey = resetCode;
      user.resetExpires = new Date(Date.now() + 3600000); // 1-hour expiry
  
      // Save the user with the updated fields
      await user.save();
  
      // Send the reset code via email
      await sendResetCodeEmail(email, resetCode);
  
      res.json({ message: 'Password reset code sent', redirectUrl: '/reset-password.html' });
    } catch (error) {
      console.error('Error processing request:', error);
      res.status(500).json({ message: 'Error processing request' });
    }
  });

 // Reset password route
app.post('/reset-password', async (req, res) => {
  const { resetKey, newPassword } = req.body;

  // Validate the new password
  if (!isValidPassword(newPassword)) {
    return res.status(400).json({
      success: false,
      message: 'Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.'
    });
  }

  try {
    const user = await users.findOne({
      resetKey: resetKey,
      resetExpires: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired reset key.' });
    }

    // Hash the new password
    const hashedPassword = hashPassword(newPassword);
    const updateResult = await users.updateOne(
      { _id: user._id },
      {
        $set: {
          password: hashedPassword,
          resetKey: null,
          resetExpires: null
        }
      }
    );

    if (updateResult.modifiedCount === 1) {
      const email = user.emaildb;

      // Optional: send a confirmation email
      await sendResetCodeEmail(email, resetKey);

      res.json({ success: true, message: 'Your password has been successfully reset.' });
    } else {
      res.status(500).json({ success: false, message: 'Password reset failed.' });
    }
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ success: false, message: 'Error resetting password' });
  }
});

// Start the Server
app.listen(PORT, () => {
  const baseUrl = `http://localhost:${PORT}`; 
  console.log(`Server is running on port ${PORT}: ${baseUrl}`); 
});
