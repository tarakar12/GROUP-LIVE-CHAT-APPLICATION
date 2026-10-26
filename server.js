// server.js (Complete File with Private Messaging and File Sharing)

// --- Required Modules ---
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config(); // Loads .env file variables
const path = require('path');
const connectDB = require('./config/db'); // Your database connection function
const Message = require('./models/Message'); // Mongoose Message model
const User = require('./models/User');     // Mongoose User model
const multer = require('multer'); // NEW: For handling file uploads

// --- Basic Setup ---
const app = express(); // Create the Express application
const server = http.createServer(app); // Create HTTP server for Socket.IO
const io = new Server(server); // Attach Socket.IO to the server

const PORT = process.env.PORT || 3000; // Define the port

// --- Database Connection ---
connectDB(); // Call the function to connect to MongoDB

// --- JWT Secret ---
// IMPORTANT: Set JWT_SECRET in your .env file for security!
const JWT_SECRET = process.env.JWT_SECRET || 'your-very-strong-secret-key-replace-me';

// --- Express Middleware ---
// Serve static files (HTML, CSS, JS) from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));
// Parse JSON request bodies
app.use(express.json());

// NEW: Serve uploaded files from the 'uploads' directory
// Files will be accessible via /uploads/<filename>
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// --- Multer Configuration for File Uploads ---
// Define storage for uploaded files
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        // Specify the directory where files will be stored
        // Make sure this 'uploads' directory exists in your project root!
        cb(null, path.join(__dirname, 'uploads'));
    },
    filename: function (req, file, cb) {
        // Generate a unique filename to prevent collisions
        // Combines current timestamp with original file extension
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

// Filter for file types (optional, but recommended for security)
const fileFilter = (req, file, cb) => {
    // Allow only specific image and document types
    const allowedMimeTypes = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'application/pdf',
        'application/msword', // .doc
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document', // .docx
        'application/vnd.ms-excel', // .xls
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', // .xlsx
        'application/vnd.ms-powerpoint', // .ppt
        'application/vnd.openxmlformats-officedocument.presentationml.presentation', // .pptx
        'text/plain'
    ];

    if (allowedMimeTypes.includes(file.mimetype)) {
        cb(null, true); // Accept file
    } else {
        cb(new Error('Invalid file type. Only images, PDFs, and common document types are allowed.'), false); // Reject file
    }
};

// Initialize multer upload middleware
const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024 // Limit file size to 5MB (adjust as needed)
    }
});

// --- JWT Authentication Middleware for HTTP Routes ---
// This middleware will protect routes that require authentication (like file upload)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Expects "Bearer TOKEN"

    if (!token) {
        console.warn('Authentication token missing for HTTP request.');
        return res.status(401).json({ message: 'Authentication token required.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification failed for HTTP request:', err.message);
            return res.status(403).json({ message: 'Invalid or expired token.' });
        }
        req.user = user; // Attach user payload (userId, username) to the request
        next();
    });
};


// --- HTTP Routes ---

// Route for the main chat page (index.html)
// Client-side JS will handle redirecting to /login if not authenticated
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Route for the login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// --- User Registration Endpoint ---
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) { /* ... validation ... */ return res.status(400).json({ message: 'Username and password required' }); }
    if (password.length < 6) { /* ... validation ... */ return res.status(400).json({ message: 'Password must be at least 6 characters' }); }
    try {
        const existingUser = await User.findOne({ username: username.toLowerCase() });
        if (existingUser) { return res.status(400).json({ message: 'Username already taken' }); }
        const newUser = new User({ username: username.toLowerCase(), password });
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) { /* ... error handling ... */ console.error('Registration Error:', error); res.status(500).json({ message: 'Server error during registration' }); }
});

// --- User Login Endpoint ---
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) { /* ... validation ... */ return res.status(400).json({ message: 'Username and password required' }); }
    try {
        const user = await User.findOne({ username: username.toLowerCase() });
        if (!user) { /* ... validation ... */ return res.status(401).json({ message: 'Invalid credentials' }); }
        const isMatch = await user.comparePassword(password);
        if (!isMatch) { /* ... validation ... */ return res.status(401).json({ message: 'Invalid credentials' }); }
        const payload = { userId: user._id, username: user.username };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, username: user.username });
    } catch (error) { /* ... error handling ... */ console.error('Login Error:', error); res.status(500).json({ message: 'Server error during login' }); }
});

// NEW: File Upload Endpoint
// This route handles incoming file uploads.
// It uses `authenticateToken` to ensure only logged-in users can upload.
// `upload.single('chatFile')` expects a single file field named 'chatFile' from the client.
app.post('/upload', authenticateToken, upload.single('chatFile'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded.' });
        }

        const senderUsername = req.user.username;
        const senderUserId = req.user.userId;
        const fileUrl = `/uploads/${req.file.filename}`; // URL to access the uploaded file
        const fileName = req.file.originalname;
        const fileMimeType = req.file.mimetype;

        console.log(`File uploaded by ${senderUsername}: ${fileName} (${fileMimeType})`);

        // Create a new message entry for the file
        const message = new Message({
            username: senderUsername,
            userId: senderUserId,
            text: `shared a file: ${fileName}`, // A default text message indicating a file share
            timestamp: new Date(),
            isPrivate: false, // For now, assume global file sharing. Can be extended for PMs.
            fileUrl: fileUrl,
            fileName: fileName,
            fileMimeType: fileMimeType
        });

        const savedMessage = await message.save();
        // Broadcast the file message to all connected clients
        io.emit('chat_message', savedMessage); // Reusing 'chat_message' for consistency, client will handle display based on fileUrl

        res.status(200).json({
            message: 'File uploaded successfully!',
            file: {
                url: fileUrl,
                name: fileName,
                mimeType: fileMimeType
            }
        });

    } catch (error) {
        if (error instanceof multer.MulterError) {
            // Multer-specific errors (e.g., file size limit exceeded)
            console.error('Multer error during file upload:', error.message);
            return res.status(400).json({ message: `File upload failed: ${error.message}` });
        } else if (error.message.includes('Invalid file type')) {
            // Custom file filter error
            console.error('File type error:', error.message);
            return res.status(400).json({ message: error.message });
        } else {
            console.error('Server error during file upload:', error);
            res.status(500).json({ message: 'Server error during file upload.' });
        }
    }
});


// --- Socket.IO Authentication Middleware ---
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) { /* ... error handling ... */ console.error('Auth Error: No token provided by', socket.id); return next(new Error('Authentication error: No token')); }
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) { /* ... error handling ... */ console.error('Auth Error: Invalid token for', socket.id, err.message); return next(new Error('Authentication error: Invalid token')); }
        socket.user = decoded; // Attach user data to socket
        console.log(`Auth Success: User ${socket.user.username} (${socket.user.userId}) authenticated for socket ${socket.id}`);
        next();
    });
});

// --- Global State (for tracking online users - consider Redis for scaling) ---
// Map username -> { socketId: socket.id, userId: ... }
let usersMap = new Map();

// --- Socket.IO Connection Handling ---
io.on('connection', (socket) => {
    const username = socket.user.username;
    const userId = socket.user.userId;
    console.log(`User connected: ${username} (${userId}) with socket ${socket.id}`);

    // --- Handle User Presence ---
    usersMap.set(username, { socketId: socket.id, userId: userId });
    const onlineUsernames = Array.from(usersMap.keys());
    io.emit('update_user_list', onlineUsernames); // Send updated list to ALL clients
    socket.emit('your_details', { username: username, userId: userId }); // Send user their details

    // --- Load Recent Global Chat History ---
    // Fetch both text messages and file messages
    Message.find({ isPrivate: false }).sort({ timestamp: -1 }).limit(50)
        .then(messages => { socket.emit('load_history', messages.reverse()); })
        .catch(err => console.error('Error loading global chat history:', err));

    // --- Handle Incoming Global Chat Messages ---
    socket.on('chat_message', async (msgText) => {
        if (!msgText || typeof msgText !== 'string' || msgText.trim().length === 0) { /* ... validation ... */ return; }
        const text = msgText.trim();
        console.log(`Global Message from ${username}: ${text}`);
        const message = new Message({
            username: username, // Sender username
            userId: userId,     // Sender user ID
            text: text,
            timestamp: new Date(),
            isPrivate: false // Explicitly false for global messages
        });
        try {
            const savedMessage = await message.save();
            io.emit('chat_message', savedMessage); // Broadcast global message to everyone
        } catch (err) {
            console.error('Error saving global message:', err);
        }
    });

    // --- Handle Private Messages ---
    socket.on('private_message', async ({ recipientUsername, text }) => {
        const senderUsername = socket.user.username;
        const senderUserId = socket.user.userId;

        // Basic validation
        if (!recipientUsername || !text || typeof text !== 'string' || text.trim().length === 0) {
            console.warn(`Invalid PM body from ${senderUsername} to ${recipientUsername}`);
            socket.emit('pm_error', { message: 'Cannot send empty message.' }); return;
        }
        if (recipientUsername === senderUsername) {
            console.warn(`User ${senderUsername} tried to PM self.`);
            socket.emit('pm_error', { message: "You can't send a private message to yourself." }); return;
        }
        text = text.trim();

        const recipientData = usersMap.get(recipientUsername); // Find recipient

        if (recipientData) { // Recipient online
            const recipientSocketId = recipientData.socketId;
            const recipientUserId = recipientData.userId;
            console.log(`Relaying PM from ${senderUsername} to ${recipientUsername} (${recipientSocketId})`);

            const messageData = { // Prepare message data
                username: senderUsername,
                userId: senderUserId,
                text: text,
                senderUsername: senderUsername,
                senderId: senderUserId,
                recipientUsername: recipientUsername,
                recipientId: recipientUserId,
                timestamp: new Date(),
                isPrivate: true
            };

            const message = new Message(messageData); // Create message model instance
            try {
                const savedMessage = await message.save(); // Save to DB
                // Emit message ONLY to recipient and sender
                io.to(recipientSocketId).emit('private_message', savedMessage);
                socket.emit('private_message', savedMessage); // Send back to sender
            } catch (err) {
                console.error('Error saving private message:', err);
                socket.emit('pm_error', { message: 'Server failed to save message.' });
            }
        } else { // Recipient offline
            console.log(`User ${recipientUsername} not online for PM from ${senderUsername}.`);
            socket.emit('pm_error', { recipientUsername: recipientUsername, message: `${recipientUsername} is currently offline.` });
        }
    });

    // --- Handle Typing Indicators --- (Could be enhanced for PMs later)
    socket.on('typing', () => { socket.broadcast.emit('user_typing', username); });
    socket.on('stopped_typing', () => { socket.broadcast.emit('user_stopped_typing', username); });

    // --- Handle Disconnect ---
    socket.on('disconnect', (reason) => {
        console.log(`User disconnected: ${username} (${socket.id}). Reason: ${reason}`);
        if (usersMap.has(username) && usersMap.get(username).socketId === socket.id) {
            usersMap.delete(username);
            const updatedOnlineUsernames = Array.from(usersMap.keys());
            io.emit('update_user_list', updatedOnlineUsernames);
            socket.broadcast.emit('user_stopped_typing', username);
            console.log(`${username} removed from online users map.`);
        } else { console.log(`${username} disconnect event for socket ${socket.id}, but user map has different/no entry.`); }
    });

}); // End io.on('connection')

// --- Start Server ---
server.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
});
