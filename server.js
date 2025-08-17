require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const socketio = require('socket.io');
const http = require('http');

// Initialize app
const app = express();
const server = http.createServer(app);
const io = socketio(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/whatsapp-clone', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// User Model
const User = mongoose.model('User', {
  username: String,
  email: String,
  password: String,
  profileImage: String,
  lastSeen: Date
});

// Message Model
const Message = mongoose.model('Message', {
  id: String,
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  text: String,
  conversation: mongoose.Schema.Types.ObjectId,
  timestamp: Date,
  read: Boolean
});

// Conversation Model
const Conversation = mongoose.model('Conversation', {
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  messages: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Message' }],
  lastUpdated: Date
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || uuidv4(),
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// Authentication Routes
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({
      username,
      email,
      password: hashedPassword,
      profileImage: '/images/default-profile.png',
      lastSeen: new Date()
    });
    
    await user.save();
    req.session.userId = user._id;
    res.status(201).json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    req.session.userId = user._id;
    user.lastSeen = new Date();
    await user.save();
    
    res.json({ success: true, user: {
      id: user._id,
      username: user.username,
      profileImage: user.profileImage
    }});
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Socket.IO Logic
const activeUsers = new Map();

io.on('connection', (socket) => {
  console.log('New connection:', socket.id);

  // Authenticate socket
  socket.on('authenticate', async (userId) => {
    try {
      const user = await User.findById(userId);
      if (!user) return socket.disconnect();

      activeUsers.set(userId.toString(), socket.id);
      socket.join(userId.toString());
      
      // Update last seen status
      user.lastSeen = new Date();
      await user.save();
      
      // Notify contacts
      const contacts = await User.find({
        _id: { $ne: userId },
        $or: [
          { followers: userId },
          { following: userId }
        ]
      });
      
      contacts.forEach(contact => {
        if (activeUsers.has(contact._id.toString())) {
          io.to(activeUsers.get(contact._id.toString())).emit('userStatus', {
            userId: userId,
            isOnline: true,
            lastSeen: null
          });
        }
      });
    } catch (err) {
      console.error('Authentication error:', err);
      socket.disconnect();
    }
  });

  // Message handling
  socket.on('sendMessage', async ({ conversationId, text }) => {
    try {
      const userId = Object.entries(activeUsers).find(([_, sid]) => sid === socket.id)?.[0];
      if (!userId) return;

      const conversation = await Conversation.findById(conversationId)
        .populate('participants');
      
      if (!conversation || !conversation.participants.some(p => p._id.toString() === userId)) {
        return socket.emit('error', 'Not in conversation');
      }

      const message = new Message({
        id: uuidv4(),
        sender: userId,
        text,
        conversation: conversationId,
        timestamp: new Date(),
        read: false
      });

      await message.save();
      
      conversation.messages.push(message._id);
      conversation.lastUpdated = new Date();
      await conversation.save();

      // Send to all participants
      conversation.participants.forEach(participant => {
        const participantId = participant._id.toString();
        if (activeUsers.has(participantId)) {
          io.to(activeUsers.get(participantId)).emit('newMessage', {
            ...message.toObject(),
            sender: { _id: userId, username: participant.username }
          });
        }
      });
    } catch (err) {
      console.error('Message error:', err);
      socket.emit('error', 'Failed to send message');
    }
  });

  // Disconnection
  socket.on('disconnect', async () => {
    const userId = Object.entries(activeUsers).find(([_, sid]) => sid === socket.id)?.[0];
    if (!userId) return;

    activeUsers.delete(userId);
    
    try {
      const user = await User.findByIdAndUpdate(userId, {
        lastSeen: new Date()
      });

      // Notify contacts
      const contacts = await User.find({
        _id: { $ne: userId },
        $or: [
          { followers: userId },
          { following: userId }
        ]
      });
      
      contacts.forEach(contact => {
        if (activeUsers.has(contact._id.toString())) {
          io.to(activeUsers.get(contact._id.toString())).emit('userStatus', {
            userId: userId,
            isOnline: false,
            lastSeen: user.lastSeen
          });
        }
      });
    } catch (err) {
      console.error('Disconnect error:', err);
    }
  });
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
