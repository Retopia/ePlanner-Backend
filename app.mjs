import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import { User, Event, ResetToken } from './db.mjs';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import { OAuth2Client } from 'google-auth-library';
import sgMail from '@sendgrid/mail';
import fetch from 'node-fetch';

dotenv.config();
let lastDBActivity = Date.now();
let nextPingInterval = getRandomInterval(MIN_INTERVAL, MAX_INTERVAL);
let isPinging = false; 

// Helper function to ping the database
async function pingDatabase() {
    try {
        await mongoose.connection.db.admin().ping();
        console.log('Database pinged successfully');
    } catch (error) {
        console.error('Error pinging database:', error);
    }
}

function getRandomInterval(min, max) {
    return Math.floor(Math.random() * (max - min + 1) + min);
}

app.use(async (req, res, next) => {
    const now = Date.now();

    if (!isPinging && now - lastDBActivity > nextPingInterval) {
        isPinging = true; // Lock to prevent multiple pings
        await pingDatabase();
        lastDBActivity = now;
        nextPingInterval = getRandomInterval(MIN_INTERVAL, MAX_INTERVAL); // Set new interval after each ping
        isPinging = false; // Unlock after ping is done
    }

    next();
});

// Setting up sendgrid
sgMail.setApiKey(process.env.SENDGRID_API_KEY);
const app = express();

// Cors allows from everywhere
app.use(cors());
app.use(express.json());

// Passport middleware
app.use(passport.initialize());

// Local strategy
passport.use(
    new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
        try {
            const user = await User.findOne({ email });
            if (!user) {
                return done(null, false, { error: 'Invalid email or password' });
            }

            const validPassword = await bcrypt.compare(password, user.passwordHash);
            if (!validPassword) {
                return done(null, false, { error: 'Invalid email or password' });
            }

            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }),
);

// JWT strategy
passport.use(
    new JwtStrategy(
        {
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: process.env.JWT_SECRET,
        },
        async (jwtPayload, done) => {
            try {
                const user = await User.findById(jwtPayload.id);
                if (!user) {
                    return done(null, false, { error: 'User not found' });
                }
                return done(null, user);
            } catch (err) {
                return done(err);
            }
        },
    ),
);

// Function for generating JWT
function generateAccessToken(user) {
    const payload = {
        id: user._id,
        username: user.username,
        email: user.email,
    };

    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
    return accessToken;
}

// Middleware for authenticating JWT
function authenticateJWT(req, res, next) {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1];

        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                return res.status(403).json({ error: 'Invalid or expired token' });
            }

            req.user = decoded;
            next();
        });
    } else {
        res.status(401).json({ error: 'No token provided' });
    }
}

// Connect to MongoDB
// Added connection pooling
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

// Handles signing in with Google
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

app.post('/users/google-signin', async (req, res) => {
    const { id_token } = req.body;

    try {
        const ticket = await client.verifyIdToken({
            idToken: id_token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        const googleId = payload['sub'];
        const email = payload['email'];
        const username = payload['name'];

        let user = await User.findOne({ googleId });

        if (!user) {
            user = new User({
                googleId,
                username,
                email,
            });

            await user.save();
        }

        const accessToken = generateAccessToken(user);

        res.json({ accessToken, username });
    } catch (err) {
        console.error('Google Sign-In error:', err);
        res.status(401).json({ error: 'Invalid Google Sign-In token' });
    }
});

app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!user) {
            return res.status(400).json({ error: info.error });
        }

        // Send JWT
        const accessToken = generateAccessToken(user);
        res.json({ accessToken, username: user.username, message: 'Logged in successfully' });
    })(req, res, next);
});

app.post('/register', async (req, res) => {
    const { email, username, password } = req.body;

    // Check if the email or username is already taken
    const emailExists = await User.findOne({ email });
    if (emailExists) {
        return res.status(400).json({ error: 'Email is already taken' });
    }

    const usernameExists = await User.findOne({ username });
    if (usernameExists) {
        return res.status(400).json({ error: 'Username is already taken' });
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // Create a new user
    // Events is empty by default
    const newUser = new User({
        email,
        username,
        passwordHash,
    });

    // Save the user to the database
    try {
        await newUser.save();
        const accessToken = generateAccessToken(newUser);
        res.status(201).json({ accessToken, message: 'User created successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/users/settings', authenticateJWT, async (req, res) => {
    const userId = req.user.id;
    const { username, oldPassword, newPassword } = req.body;

    try {
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (user.googleId) {
            // Google users don't have passwords, just update the username
            user.username = username;
            await user.save();
            return res.json({ message: 'Settings updated successfully' });
        } else {
            if (oldPassword && newPassword) {
                // Check if the old password is correct
                const isPasswordValid = await bcrypt.compare(oldPassword, user.passwordHash);

                if (!isPasswordValid) {
                    return res.status(400).json({ error: 'Invalid old password' });
                }

                // Update the user's password
                const salt = await bcrypt.genSalt(10);
                const passwordHash = await bcrypt.hash(newPassword, salt);
                user.passwordHash = passwordHash;
            }

            // Update the user's username
            if (username) {
                user.username = username;
            }

            await user.save();
            return res.json({ message: 'Settings updated successfully' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Create a new route for fetching events
// This should be called by the home page
app.post('/events', async (req, res) => {
    try {
        // Get the username from the request body
        const { username } = req.body;

        // Find the user with the given username
        const user = await User.findOne({ username });

        // Check if the user exists
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Find all events created by the user
        const events = await Event.find({ creator: user._id });

        // Send the events as a response
        res.json(events);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// The intial fetching of the event data by EditEvent
app.get('/events/edit/:id', authenticateJWT, async (req, res) => {
    try {
        const event = await Event.findById(req.params.id);
        console.log(event);
        if (!event) {
            return res.status(404).json({ error: 'Event not found' });
        }

        // Check if the user is authorized to access the event
        if (event.creator.toString() !== req.user.id) {
            return res.status(403).json({ error: 'Forbidden: You are not authorized to view this event.' });
        }

        res.json(event);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Viewing the event page of a single event
app.get('/events/view/:id', async (req, res, next) => {
    try {
        let event = await Event.findById(req.params.id).populate('creator', 'username');
        if (!event) {
            return res.status(404).json({ error: 'Event not found' });
        }

        // If the event's creator is not found, set the creator to "Deleted User"
        if (!event.creator) {
            event = event.toObject(); // Convert the event to a plain object to modify its properties
            event.creator = "Deleted User";
        } else {
            event = event.toObject();
            event.creator = event.creator.username;
        }

        // If the event is public, skip authentication
        if (event.visibility === 'public') {
            return res.json(event);
        }

        // If the event is private, apply the JWT authentication middleware
        authenticateJWT(req, res, next);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Handles viewing all public events
app.get('/events/view', async (req, res) => {
    try {
        const events = await Event.find({ visibility: 'public' });
        res.json(events);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Handles creating a new event
app.post('/events/create', authenticateJWT, async (req, res) => {
    const { title, date, description, tags, location, visibility, embeddedFiles } = req.body;
    const userId = req.user.id;

    try {
        const newEvent = new Event({
            creator: userId,
            title,
            description,
            location,
            time: date,
            tags,
            visibility,
            embeddedFiles,
        });

        await newEvent.save();
        res.status(201).json({ message: 'Event created successfully', event: newEvent });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Handles updating an existing event
app.put('/events/edit/:id', authenticateJWT, async (req, res) => {
    const { title, date, description, tags, location, visibility, embeddedFiles } = req.body;
    const eventId = req.params.id;
    const userId = req.user.id;

    try {
        const event = await Event.findById(eventId);
        if (!event) {
            return res.status(404).json({ error: 'Event not found' });
        }

        if (event.creator.toString() !== userId) {
            return res.status(403).json({ error: 'You are not allowed to edit this event' });
        }

        event.title = title;
        event.description = description;
        event.location = location;
        event.time = date;
        event.tags = tags;
        event.visibility = visibility;
        event.embeddedFiles = embeddedFiles;

        await event.save();
        res.json({ message: 'Event updated successfully', event });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete an existing event
app.delete('/events/:id', authenticateJWT, async (req, res) => {
    const userId = req.user.id;
    const eventId = req.params.id;

    try {
        const event = await Event.findById(eventId);

        if (!event) {
            return res.status(404).json({ error: 'Event not found' });
        }

        if (event.creator.toString() !== userId) {
            return res.status(403).json({ error: 'You are not allowed to edit this event' });
        }

        const result = await Event.findByIdAndDelete(eventId);

        res.json({ message: 'Event deleted successfully', event: result });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Generate a random alphanumeric token of length 'length'
function generateToken(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

app.post('/forgot-password', async (req, res) => {
    const { email, captcha } = req.body;

    // Verify reCAPTCHA
    const captchaResponse = await fetch(`https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${captcha}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
    });

    const captchaData = await captchaResponse.json();

    if (!captchaData.success) {
        return res.status(400).json({ error: 'Invalid captcha' });
    }

    try {
        // Find the user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        // Generate a token and create a new ResetToken document
        const token = generateToken(32);
        const resetToken = new ResetToken({
            userId: user._id,
            token,
        });

        // Send the reset password email with the token
        const resetLink = process.env.FRONTEND_ADDRESS + `/reset-password/${token}`;
        const msg = {
            to: email,
            from: 'noreply.eplanner@gmail.com',
            subject: 'Reset Your Password',
            text: `Please use the following link to reset your password: ${resetLink}`,
            html: `<p>Please use the following link to reset your password:</p><a href="${resetLink}">${resetLink}</a>`,
        };
        console.log('Sending email...');
        await sgMail.send(msg);
        console.log('Email sent.');

        res.status(200).json({ message: 'Password reset email sent' });

        // Finally we save the token
        await resetToken.save();
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/reset-password', async (req, res) => {
    const { token, password } = req.body;

    try {
        const resetToken = await ResetToken.findOne({ token });

        if (!resetToken) {
            return res.status(400).json({ error: 'Invalid token' });
        }

        // Check if the token has expired (e.g., after 1 hour)
        const tokenAge = Date.now() - resetToken.createdAt;
        if (tokenAge > 60 * 60 * 1000) {
            await ResetToken.deleteOne({ token });
            return res.status(400).json({ error: 'Token has expired' });
        }

        const user = await User.findById(resetToken.userId);
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        // Update the user's password
        const salt = await bcrypt.genSalt(10);
        user.passwordHash = await bcrypt.hash(password, salt);
        await user.save();

        // Delete the token from the resetToken collection
        await ResetToken.deleteOne({ token });

        res.status(200).json({ message: 'Password updated successfully' });
    } catch (error) {
        console.log(error)
        res.status(500).json({ error: 'Server error' });
    }
});

// Validates passord reset token
app.get('/validate-reset-token/:token', async (req, res) => {
    const { token } = req.params;

    try {
        const resetToken = await ResetToken.findOne({ token });

        if (!resetToken) {
            return res.status(400).json({ error: 'Invalid token' });
        }

        // Check if the token has expired (e.g., after 1 hour)
        const tokenAge = Date.now() - resetToken.createdAt;
        if (tokenAge > 60 * 60 * 1000) {
            await ResetToken.deleteOne({ token });
            return res.status(400).json({ error: 'Token has expired' });
        }

        // If the token is valid and not expired, send a success status
        res.status(200).json({ message: 'Token is valid' });
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// For reset password to check if the user is a Google user
app.get('/is-google-user/:email', async (req, res) => {
    const { email } = req.params;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        // Truthy casting
        const isGoogleUser = !!user.googleId;
        res.status(200).json({ isGoogleUser });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Run the server and print out
app.listen(process.env.PORT || 4000, () => {
    console.log(`Server is running on port ${process.env.PORT || 4000}`);
});
