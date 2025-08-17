require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const expressLayouts = require('express-ejs-layouts');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const { getLinkPreview } = require('link-preview-js');
const http = require('http');
const socketio = require('socket.io');

// Initialize app & sockets
const app = express();
const server = http.createServer(app);
const io = socketio(server, {
  cors: { origin: '*', methods: ['GET','POST'] }
});

// Trust proxy for Heroku/Render
app.set('trust proxy', 1);

// Fail-fast on fatal errors
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

// ============================
// MongoDB connection
// ============================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/bbwhatsapp';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  retryWrites: true,
  w: 'majority'
})
.then(() => console.log('MongoDB Connected'))
.catch(err => console.error('MongoDB connection error:', err));

mongoose.connection.on('error', err => console.error('MongoDB connection error:', err));
mongoose.connection.on('disconnected', () => console.log('MongoDB disconnected'));

// ============================
// Models (as in your project)
// ============================
const User = require('./models/User');
const Message = require('./models/Message');
const Conversation = require('./models/Conversation');

// ============================
// Multer (memory storage)
// ============================
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg','image/png','image/gif','video/mp4','audio/mpeg'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Invalid file type'), false);
  }
});

// ============================
// Express & EJS
// ============================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(expressLayouts);

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.set('layout', 'layouts/layout');

// ============================
// Session
// ============================
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-here-' + uuidv4(),
  store: new MemoryStore({ checkPeriod: 86400000 }),
  resave: true,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// Current user into locals
app.use((req, res, next) => {
  res.locals.currentUser = req.session.user;
  next();
});

// ============================
// Routes
// ============================

// Home redirect
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/home');
  res.redirect('/login');
});

// Home w/ conversations + latest group slice
app.get('/home', async (req, res, next) => {
  try {
    if (!req.session.user || !req.session.user.id) return res.redirect('/login');

    const user = await User.findById(req.session.user.id)
      .populate('following', 'username profileImage status')
      .populate('followers', 'username profileImage status');

    if (!user) {
      req.session.destroy(() => {});
      return res.redirect('/login');
    }

    const groupMessages = await Message.find({
      type: 'chat',
      $or: [{ deleted: false }, { type: 'system' }]
    })
    .sort({ createdAt: -1 })
    .limit(100)
    .populate('sender', 'username profileImage');

    const conversations = await Conversation.find({
      participants: req.session.user.id
    })
    .populate('participants', 'username profileImage status')
    .populate({
      path: 'messages',
      options: { sort: { createdAt: -1 }, limit: 1 },
      populate: { path: 'sender', select: 'username profileImage' }
    })
    .sort({ updatedAt: -1 });

    res.render('home', {
      title: 'BBWhatsApp - Home',
      user,
      groupMessages: groupMessages.reverse(),
      conversations
    });
  } catch (err) {
    next(err);
  }
});

// Chat (group or 1:1 by conversationId)
app.get('/chat/:conversationId?', async (req, res, next) => {
  try {
    if (!req.session.user || !req.session.user.id) return res.redirect('/login');

    const conversationId = req.params.conversationId;
    let messages = [];
    let conversation = null;
    let otherUser = null;

    if (conversationId) {
      conversation = await Conversation.findById(conversationId)
        .populate('participants', 'username profileImage status');

      if (
        !conversation ||
        !conversation.participants.some(p => p._id.toString() === req.session.user.id.toString())
      ) {
        return res.status(403).send('Access denied');
      }

      otherUser = conversation.participants.find(p => p._id.toString() !== req.session.user.id.toString());

      messages = await Message.find({
        conversation: conversationId,
        deleted: false
      })
      .sort({ createdAt: 1 })
      .populate('sender', 'username profileImage');
    } else {
      messages = await Message.find({
        type: 'chat',
        $or: [{ deleted: false }, { type: 'system' }]
      })
      .sort({ createdAt: 1 })
      .limit(100)
      .populate('sender', 'username profileImage');
    }

    // Expose identifiers to the view for chat.js
    res.render('chat', {
      title: conversationId ? `Chat with ${otherUser?.username}` : 'BBWhatsApp Group',
      username: req.session.user.username,
      userId: req.session.user.id,
      messages,
      conversation,
      otherUser,
      isGroup: !conversationId
    });
  } catch (err) {
    next(err);
  }
});

// Profile
app.get('/profile/:userId?', async (req, res, next) => {
  try {
    if (!req.session.user || !req.session.user.id) return res.redirect('/login');

    const userId = req.params.userId || req.session.user.id;
    const user = await User.findById(userId)
      .select('-password')
      .populate('following', 'username profileImage')
      .populate('followers', 'username profileImage');

    if (!user) return res.status(404).send('User not found');

    const isOwnProfile = userId.toString() === req.session.user.id.toString();
    const isFollowing = !isOwnProfile &&
      Array.isArray(req.session.user.following) &&
      req.session.user.following.some(u => u._id?.toString?.() === user._id.toString());

    res.render('profile', {
      title: `${user.username}'s Profile`,
      profileUser: user,
      isOwnProfile,
      isFollowing
    });
  } catch (err) {
    next(err);
  }
});

// Update Profile
app.post('/profile/update', upload.single('profileImage'), async (req, res, next) => {
  try {
    if (!req.session.user || !req.session.user.id) return res.redirect('/login');

    const { username, status } = req.body;
    const updateData = { username, status };

    if (req.file) {
      updateData.profileImage = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
      // TODO: delete old profile image from cloud storage if needed
    }

    await User.findByIdAndUpdate(req.session.user.id, updateData);

    // Refresh session
    const updatedUser = await User.findById(req.session.user.id);
    req.session.user = {
      id: updatedUser._id,
      username: updatedUser.username,
      email: updatedUser.email,
      profileImage: updatedUser.profileImage,
      following: updatedUser.following
    };

    req.session.save(err => {
      if (err) return next(err);
      res.redirect(`/profile/${req.session.user.id}`);
    });
  } catch (err) {
    next(err);
  }
});

// Follow / Unfollow
app.post('/follow/:userId', async (req, res, next) => {
  try {
    if (!req.session.user || !req.session.user.id) return res.redirect('/login');
    const userIdToFollow = req.params.userId;

    if (userIdToFollow === req.session.user.id.toString()) {
      return res.status(400).send('Cannot follow yourself');
    }

    await User.findByIdAndUpdate(req.session.user.id, { $addToSet: { following: userIdToFollow }});
    await User.findByIdAndUpdate(userIdToFollow, { $addToSet: { followers: req.session.user.id }});

    const updatedUser = await User.findById(req.session.user.id);
    req.session.user.following = updatedUser.following;

    req.session.save(err => {
      if (err) return next(err);
      res.redirect(`/profile/${userIdToFollow}`);
    });
  } catch (err) {
    next(err);
  }
});

app.post('/unfollow/:userId', async (req, res, next) => {
  try {
    if (!req.session.user || !req.session.user.id) return res.redirect('/login');
    const userIdToUnfollow = req.params.userId;

    await User.findByIdAndUpdate(req.session.user.id, { $pull: { following: userIdToUnfollow }});
    await User.findByIdAndUpdate(userIdToUnfollow, { $pull: { followers: req.session.user.id }});

    const updatedUser = await User.findById(req.session.user.id);
    req.session.user.following = updatedUser.following;

    req.session.save(err => {
      if (err) return next(err);
      res.redirect(`/profile/${userIdToUnfollow}`);
    });
  } catch (err) {
    next(err);
  }
});

// Start 1:1 conversation
app.get('/new-chat/:userId', async (req, res, next) => {
  try {
    if (!req.session.user || !req.session.user.id) return res.redirect('/login');

    const otherUserId = req.params.userId;
    if (otherUserId === req.session.user.id.toString()) {
      return res.status(400).send('Cannot chat with yourself');
    }

    let conversation = await Conversation.findOne({
      participants: { $all: [req.session.user.id, otherUserId], $size: 2 }
    });

    if (!conversation) {
      conversation = new Conversation({
        participants: [req.session.user.id, otherUserId]
      });
      await conversation.save();
    }

    res.redirect(`/chat/${conversation._id}`);
  } catch (err) {
    next(err);
  }
});

// Auth pages
app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/home');
  res.render('login', { title: 'Login - BBWhatsApp', error: null });
});

app.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.render('login', { title: 'Login - BBWhatsApp', error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render('login', { title: 'Login - BBWhatsApp', error: 'Invalid credentials' });
    }

    req.session.user = {
      id: user._id,
      username: user.username,
      email: user.email,
      profileImage: user.profileImage,
      following: user.following
    };

    req.session.save(err => {
      if (err) return next(err);
      res.redirect('/home');
    });
  } catch (err) {
    next(err);
  }
});

app.get('/register', (req, res) => {
  if (req.session.user) return res.redirect('/home');
  res.render('register', { title: 'Register - BBWhatsApp', error: null });
});

app.post('/register', upload.single('profileImage'), async (req, res, next) => {
  try {
    const { username, email, password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
      return res.render('register', { title: 'Register - BBWhatsApp', error: 'Passwords do not match' });
    }

    const existingEmail = await User.findOne({ email });
    const existingUsername = await User.findOne({ username });

    if (existingEmail) {
      return res.render('register', { title: 'Register - BBWhatsApp', error: 'Email already exists. Please login instead.' });
    }
    if (existingUsername) {
      return res.render('register', { title: 'Register - BBWhatsApp', error: 'Username already taken. Please choose another.' });
    }

    const profileImage = req.file
      ? `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`
      : '/images/profiles/default-profile.png';

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({ username, email, password: hashedPassword, profileImage });
    await user.save();

    req.session.user = {
      id: user._id,
      username: user.username,
      email: user.email,
      profileImage: user.profileImage,
      following: user.following
    };

    req.session.save(err => {
      if (err) return next(err);
      res.redirect('/home');
    });
  } catch (err) {
    next(err);
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Session destruction error:', err);
      return res.status(500).send('Server Error');
    }
    res.redirect('/login');
  });
});

// Uploads (inline base64)
app.post('/upload', upload.single('media'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({
    url: `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`,
    type: req.file.mimetype.split('/')[0]
  });
});

// ============================
// Errors
// ============================
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render('error', {
    title: 'Error',
    message: 'Something went wrong!',
    error: process.env.NODE_ENV === 'development' ? err : { message: err.message }
  });
});

app.use((req, res) => {
  res.status(404).render('error', {
    title: 'Not Found',
    message: 'Page not found',
    error: { message: 'The requested page could not be found.' }
  });
});

// ============================
// Socket.IO
// ============================
const activeUsers = new Map();    // userId -> socketId
const typingUsers = new Map();    // conversationId -> Set<userId>

io.on('connection', (socket) => {
  let currentUserId = null;

  // Join app (by userId)
  socket.on('join', async (userId) => {
    if (!userId) return;

    currentUserId = userId.toString();
    activeUsers.set(currentUserId, socket.id);
    socket.join(currentUserId);

    try {
      const user = await User.findById(currentUserId).populate('following', '_id');
      if (user) {
        user.following.forEach(contact => {
          const cId = contact._id.toString();
          if (activeUsers.has(cId)) {
            io.to(activeUsers.get(cId)).emit('userStatus', {
              userId: currentUserId,
              isOnline: true,
              lastSeen: null
            });
          }
        });
      }
    } catch (err) {
      console.error('Socket join error:', err);
    }
  });

  // Join a conversation room
  socket.on('joinConversation', async (conversationId) => {
    if (!conversationId || !currentUserId) return;

    try {
      const conversation = await Conversation.findById(conversationId);
      if (
        !conversation ||
        !conversation.participants.some(p => p.toString() === currentUserId)
      ) {
        return;
      }

      socket.join(conversationId);

      // mark unread as read for this user
      await Message.updateMany(
        {
          conversation: conversationId,
          sender: { $ne: currentUserId },
          read: false
        },
        { $set: { read: true }, $addToSet: { readBy: currentUserId } }
      );

      // notify others
      conversation.participants.forEach(pid => {
        const pidStr = pid.toString();
        if (pidStr !== currentUserId && activeUsers.has(pidStr)) {
          io.to(activeUsers.get(pidStr)).emit('messagesRead', {
            conversationId,
            readerId: currentUserId
          });
        }
      });
    } catch (err) {
      console.error('Join conversation error:', err);
    }
  });

  socket.on('leaveConversation', (conversationId) => {
    if (conversationId) socket.leave(conversationId);
  });

  // Send message
  socket.on('chatMessage', async (msg) => {
    if (!currentUserId) return;

    try {
      let conversation;
      let isGroup = false;

      if (msg.conversationId) {
        conversation = await Conversation.findById(msg.conversationId);
        if (
          !conversation ||
          !conversation.participants.some(p => p.toString() === currentUserId)
        ) {
          return;
        }
      } else {
        // group message only if user follows someone (your rule)
        const user = await User.findById(currentUserId);
        if (!user || user.following.length === 0) return;
        isGroup = true;
      }

      // reply payload
      let replyTo = null;
      if (msg.replyTo?.id) {
        const original = await Message.findOne({ id: msg.replyTo.id });
        if (original) {
          replyTo = {
            messageId: original.id,
            senderId: original.sender,
            text: original.text
          };
        }
      }

      // link preview
      let linkPreview = null;
      if (msg.text) {
        const urlRegex = /(https?:\/\/[^\s]+)/g;
        const urls = msg.text.match(urlRegex);
        if (urls && urls.length > 0) {
          try {
            const preview = await getLinkPreview(urls[0]);
            linkPreview = {
              url: urls[0],
              title: preview.title || '',
              description: preview.description || '',
              image: Array.isArray(preview.images) && preview.images.length ? preview.images[0] : null,
              domain: new URL(urls[0]).hostname.replace('www.', '')
            };
          } catch (err) {
            console.error('Link preview error:', err);
          }
        }
      }

      const message = new Message({
        id: uuidv4(),
        conversation: msg.conversationId || null,
        sender: currentUserId,
        text: msg.text,
        type: isGroup ? 'chat' : 'private',
        replyTo,
        media: msg.media || null,
        linkPreview,
        reactions: {},
        read: false,
        readBy: [],
        pinned: false,
        edited: false,
        deleted: false
      });

      await message.save();

      if (!isGroup) {
        conversation.updatedAt = new Date();
        conversation.messages.push(message._id);
        await conversation.save();
      }

      const populatedMessage = await Message.findById(message._id)
        .populate('sender', 'username profileImage');

      if (isGroup) {
        io.emit('message', populatedMessage);
      } else {
        io.to(msg.conversationId).emit('message', populatedMessage);

        // notify participants not currently in the room
        conversation.participants.forEach(participantId => {
          const pid = participantId.toString();
          if (pid === currentUserId) return;
          const room = socket.adapter.rooms.get(msg.conversationId); // Set of socketIds
          const targetSocketId = activeUsers.get(pid);
          const inRoom = room && targetSocketId && room.has(targetSocketId);

          if (!inRoom && activeUsers.has(pid)) {
            io.to(targetSocketId).emit('newMessageNotification', {
              conversationId: msg.conversationId,
              message: populatedMessage
            });
          }
        });
      }

      // naive auto-read if multiple present or group
      setTimeout(async () => {
        try {
          const room = msg.conversationId ? socket.adapter.rooms.get(msg.conversationId) : null;
          if (isGroup || (room && room.size > 1)) {
            message.read = true;
            if (!Array.isArray(message.readBy)) message.readBy = [];
            if (!message.readBy.includes(currentUserId)) message.readBy.push(currentUserId);
            await message.save();

            if (isGroup) {
              io.emit('messageUpdated', message);
            } else {
              io.to(msg.conversationId).emit('messageUpdated', message);
            }
          }
        } catch (err) {
          console.error('Message read update error:', err);
        }
      }, 2000);
    } catch (err) {
      console.error('Chat message error:', err);
    }
  });

  // Edit message
  socket.on('editMessage', async (data) => {
    try {
      const message = await Message.findOne({ id: data.messageId }).populate('sender', '_id');
      if (message && message.sender._id.toString() === currentUserId) {
        message.text = data.newText;
        message.edited = true;
        await message.save();

        if (message.type === 'chat') {
          io.emit('messageUpdated', message);
        } else {
          io.to(message.conversation.toString()).emit('messageUpdated', message);
        }
      }
    } catch (err) {
      console.error('Edit message error:', err);
    }
  });

  // Delete message
  socket.on('deleteMessage', async (data) => {
    try {
      const message = await Message.findOne({ id: data.messageId }).populate('sender', '_id');
      if (message && message.sender._id.toString() === currentUserId) {
        message.deleted = true;
        message.text = 'This message was deleted';
        await message.save();

        if (message.type === 'chat') {
          io.emit('messageUpdated', message);
        } else {
          io.to(message.conversation.toString()).emit('messageUpdated', message);
        }
      }
    } catch (err) {
      console.error('Delete message error:', err);
    }
  });

  // Reactions
  socket.on('reactToMessage', async (data) => {
    try {
      const message = await Message.findOne({ id: data.messageId });
      if (message) {
        if (!message.reactions[data.icon]) {
          message.reactions[data.icon] = [];
        }

        const idx = message.reactions[data.icon].indexOf(currentUserId);
        if (idx > -1) {
          message.reactions[data.icon].splice(idx, 1);
          if (message.reactions[data.icon].length === 0) {
            delete message.reactions[data.icon];
          }
        } else {
          message.reactions[data.icon].push(currentUserId);
        }

        await message.save();

        if (message.type === 'chat') {
          io.emit('messageUpdated', message);
        } else {
          io.to(message.conversation.toString()).emit('messageUpdated', message);
        }
      }
    } catch (err) {
      console.error('React to message error:', err);
    }
  });

  // Typing indicator
  socket.on('typing', (data) => {
    if (!currentUserId || !data.conversationId) return;

    try {
      const isTyping = data.isTyping !== false;

      if (isTyping) {
        if (!typingUsers.has(data.conversationId)) {
          typingUsers.set(data.conversationId, new Set());
        }
        typingUsers.get(data.conversationId).add(currentUserId);
      } else if (typingUsers.has(data.conversationId)) {
        typingUsers.get(data.conversationId).delete(currentUserId);
        if (typingUsers.get(data.conversationId).size === 0) {
          typingUsers.delete(data.conversationId);
        }
      }

      const currentTyping = typingUsers.has(data.conversationId)
        ? Array.from(typingUsers.get(data.conversationId))
        : [];

      socket.to(data.conversationId).emit('typing', {
        conversationId: data.conversationId,
        userId: currentUserId,
        isTyping,
        typingUsers: currentTyping
      });
    } catch (err) {
      console.error('Typing indicator error:', err);
    }
  });

  // Disconnect
  socket.on('disconnect', async () => {
    if (currentUserId) {
      activeUsers.delete(currentUserId);

      try {
        const user = await User.findByIdAndUpdate(
          currentUserId,
          { lastSeen: new Date() },
          { new: true }
        ).populate('following', '_id');

        if (user) {
          user.following.forEach(contact => {
            const cId = contact._id.toString();
            if (activeUsers.has(cId)) {
              io.to(activeUsers.get(cId)).emit('userStatus', {
                userId: currentUserId,
                isOnline: false,
                lastSeen: user.lastSeen
              });
            }
          });
        }
      } catch (err) {
        console.error('Disconnect error:', err);
      }
    }
  });
});

// ============================
// Start server
// ============================
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
