// server.js
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
const socketIo = require('socket.io');

// Initialize app
const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Trust proxy for Heroku (if used)
app.set('trust proxy', 1);

// Crash on uncaught exceptions in dev to see stack
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

// --------------------
// MongoDB connection
// --------------------
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/bbwhatsapp';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  retryWrites: true,
  w: 'majority'
})
.then(() => console.log('MongoDB Connected'))
.catch(err => console.error('MongoDB connection error:', err));

mongoose.connection.on('error', err => {
  console.error('MongoDB connection error:', err);
});
mongoose.connection.on('disconnected', () => {
  console.log('MongoDB disconnected');
});

// --------------------
// Models (your project should have these files)
// --------------------
const User = require('./models/User');
const Message = require('./models/Message');
const Conversation = require('./models/Conversation');

// --------------------
// Multer (memory storage)
// --------------------
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'video/mp4', 'audio/mpeg'];
    if (allowedTypes.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Invalid file type'), false);
  }
});

// --------------------
// Express middleware and view engine
// --------------------
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(expressLayouts);

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.set('layout', 'layouts/layout');

// --------------------
// Session
// --------------------
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

// expose current user to views
app.use((req, res, next) => {
  res.locals.currentUser = req.session.user;
  next();
});

// --------------------
// Routes (same structure as your original app)
// --------------------

// Home route
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/home');
  res.redirect('/login');
});

// Home with conversations & group messages
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

// Chat page (group or conversation)
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

      if (!conversation || !conversation.participants.some(p => p._id.toString() === req.session.user.id.toString())) {
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
      // group
      messages = await Message.find({
        type: 'chat',
        $or: [{ deleted: false }, { type: 'system' }]
      })
        .sort({ createdAt: 1 })
        .limit(100)
        .populate('sender', 'username profileImage');
    }

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

// Profile page
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
      req.session.user.following &&
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

// Update profile
app.post('/profile/update', upload.single('profileImage'), async (req, res, next) => {
  try {
    if (!req.session.user || !req.session.user.id) return res.redirect('/login');

    const { username, status } = req.body;
    const updateData = { username, status };

    if (req.file) {
      updateData.profileImage = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
      // Optionally delete old image from storage if needed
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

// New 1:1 chat
app.get('/new-chat/:userId', async (req, res, next) => {
  try {
    if (!req.session.user || !req.session.user.id) return res.redirect('/login');

    const otherUserId = req.params.userId;
    if (otherUserId === req.session.user.id.toString()) return res.status(400).send('Cannot chat with yourself');

    let conversation = await Conversation.findOne({
      participants: { $all: [req.session.user.id, otherUserId], $size: 2 }
    });

    if (!conversation) {
      conversation = new Conversation({ participants: [req.session.user.id, otherUserId] });
      await conversation.save();
    }

    res.redirect(`/chat/${conversation._id}`);
  } catch (err) {
    next(err);
  }
});

// Login / Register
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

// File upload endpoint (returns base64 data URI)
app.post('/upload', upload.single('media'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({
    url: `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`,
    type: req.file.mimetype.split('/')[0]
  });
});

// --------------------
// Error handlers & 404
// --------------------
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

// --------------------
// Socket.IO Implementation (supports multiple sockets per user)
// --------------------
/**
 * activeUsers: Map<userId, Set<socketId>>
 * socketUser: Map<socketId, userId>
 * typingUsers: Map<conversationId, Set<userId>>
 */
const activeUsers = new Map();
const socketUser = new Map();
const typingUsers = new Map();

io.on('connection', (socket) => {
  let currentUserId = null;

  // client should emit 'join' passing userId (from session)
  socket.on('join', async (userId) => {
    if (!userId) return;
    currentUserId = userId.toString();

    // track mapping userId -> set of socketIds
    if (!activeUsers.has(currentUserId)) activeUsers.set(currentUserId, new Set());
    activeUsers.get(currentUserId).add(socket.id);
    socketUser.set(socket.id, currentUserId);

    // join a private room for the user so we can emit direct notifications
    socket.join(`user:${currentUserId}`);

    // notify followers/contacts if you want to
    try {
      const user = await User.findById(currentUserId).populate('following', '_id');
      if (user) {
        user.following.forEach(contact => {
          const cid = contact._id.toString();
          if (activeUsers.has(cid)) {
            // notify online status to the contact's sockets
            [...activeUsers.get(cid)].forEach(sid => {
              io.to(sid).emit('userStatus', {
                userId: currentUserId,
                isOnline: true,
                lastSeen: null
              });
            });
          }
        });
      }
    } catch (err) {
      console.error('Socket join error:', err);
    }
  });

  // join a conversation room (group or private conversation id)
  socket.on('joinConversation', async (conversationId) => {
    if (!conversationId || !currentUserId) return;

    try {
      const conversation = await Conversation.findById(conversationId);
      if (!conversation) {
        // unknown conversation - ignore
        return;
      }

      // ensure user is participant if private
      const isParticipant = conversation.participants.some(p => p.toString() === currentUserId);
      if (!isParticipant) return;

      socket.join(conversationId);

      // mark unread messages as read by this user
      await Message.updateMany(
        {
          conversation: conversationId,
          sender: { $ne: currentUserId },
          read: false
        },
        {
          $set: { read: true },
          $addToSet: { readBy: currentUserId }
        }
      );

      // notify other participants that messages were read
      conversation.participants.forEach(pid => {
        const pidStr = pid.toString();
        if (pidStr !== currentUserId && activeUsers.has(pidStr)) {
          [...activeUsers.get(pidStr)].forEach(sid => {
            io.to(sid).emit('messagesRead', {
              conversationId,
              readerId: currentUserId
            });
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

  // chatMessage: supports group (no conversationId -> type 'chat') and private (conversationId present)
  socket.on('chatMessage', async (msg) => {
    if (!currentUserId) return;
    try {
      let conversation = null;
      let isGroup = false;

      if (msg.conversationId) {
        conversation = await Conversation.findById(msg.conversationId);
        if (!conversation || !conversation.participants.some(p => p.toString() === currentUserId)) return;
      } else {
        // group message
        isGroup = true;
      }

      // replyTo processing
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

      // link preview (first url only)
      let linkPreview = null;
      if (msg.text) {
        const urlRegex = /(https?:\/\/[^\s]+)/g;
        const urls = msg.text.match(urlRegex);
        if (urls && urls.length) {
          try {
            const preview = await getLinkPreview(urls[0]);
            linkPreview = {
              url: urls[0],
              title: preview.title || '',
              description: preview.description || '',
              image: (preview.images && preview.images.length) ? preview.images[0] : null,
              domain: new URL(urls[0]).hostname.replace('www.', '')
            };
          } catch (err) {
            console.error('Link preview error:', err.message || err);
          }
        }
      }

      // create message document
      const messageDoc = new Message({
        id: uuidv4(),
        conversation: msg.conversationId || null,
        sender: currentUserId,
        text: msg.text || '',
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

      await messageDoc.save();

      // if private, append message id to conversation
      if (!isGroup && conversation) {
        conversation.updatedAt = new Date();
        conversation.messages.push(messageDoc._id);
        await conversation.save();
      }

      // populate sender for emitting
      const populatedMessage = await Message.findById(messageDoc._id).populate('sender', 'username profileImage');

      // Broadcast
      if (isGroup) {
        io.emit('message', populatedMessage);
      } else {
        // emit to the conversation room
        io.to(msg.conversationId).emit('message', populatedMessage);

        // Notify participants who are not in the room (send to their user:<id> rooms)
        conversation.participants.forEach(participantId => {
          const pid = participantId.toString();
          if (pid === currentUserId) return;

          // check if any of participant's sockets are in conversation room
          const room = socket.adapter.rooms.get(msg.conversationId);
          let participantInRoom = false;
          if (room && activeUsers.has(pid)) {
            for (const sid of activeUsers.get(pid)) {
              if (room.has(sid)) {
                participantInRoom = true;
                break;
              }
            }
          }

          if (!participantInRoom && activeUsers.has(pid)) {
            // send new message notification to all sockets of participant
            for (const sid of activeUsers.get(pid)) {
              io.to(sid).emit('newMessageNotification', {
                conversationId: msg.conversationId,
                message: populatedMessage
              });
            }
          }
        });
      }

      // auto mark read if room has >1 socket (naive)
      setTimeout(async () => {
        try {
          const room = msg.conversationId ? socket.adapter.rooms.get(msg.conversationId) : socket.adapter.rooms.get('group');
          if (isGroup || (room && room.size > 1)) {
            messageDoc.read = true;
            if (!Array.isArray(messageDoc.readBy)) messageDoc.readBy = [];
            if (!messageDoc.readBy.includes(currentUserId)) messageDoc.readBy.push(currentUserId);
            await messageDoc.save();

            if (isGroup) {
              io.emit('messageUpdated', messageDoc);
            } else {
              io.to(msg.conversationId).emit('messageUpdated', messageDoc);
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

  // editMessage
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

  // deleteMessage
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

  // reactToMessage
  socket.on('reactToMessage', async (data) => {
    try {
      const message = await Message.findOne({ id: data.messageId });
      if (!message) return;

      if (!message.reactions) message.reactions = {};

      if (!Array.isArray(message.reactions[data.icon])) message.reactions[data.icon] = [];

      const idx = message.reactions[data.icon].indexOf(currentUserId);
      if (idx > -1) {
        message.reactions[data.icon].splice(idx, 1);
        if (message.reactions[data.icon].length === 0) delete message.reactions[data.icon];
      } else {
        message.reactions[data.icon].push(currentUserId);
      }

      await message.save();

      if (message.type === 'chat') {
        io.emit('messageUpdated', message);
      } else {
        io.to(message.conversation.toString()).emit('messageUpdated', message);
      }
    } catch (err) {
      console.error('React to message error:', err);
    }
  });

  // typing indicator
  socket.on('typing', (data) => {
    if (!currentUserId || !data.conversationId) return;
    try {
      const isTyping = data.isTyping !== false;
      if (isTyping) {
        if (!typingUsers.has(data.conversationId)) typingUsers.set(data.conversationId, new Set());
        typingUsers.get(data.conversationId).add(currentUserId);
      } else if (typingUsers.has(data.conversationId)) {
        typingUsers.get(data.conversationId).delete(currentUserId);
        if (typingUsers.get(data.conversationId).size === 0) typingUsers.delete(data.conversationId);
      }

      const currentTypingUsers = typingUsers.has(data.conversationId) ? Array.from(typingUsers.get(data.conversationId)) : [];
      socket.to(data.conversationId).emit('typing', {
        conversationId: data.conversationId,
        userId: currentUserId,
        isTyping,
        typingUsers: currentTypingUsers
      });
    } catch (err) {
      console.error('Typing indicator error:', err);
    }
  });

  // disconnect handling
  socket.on('disconnect', async () => {
    if (!currentUserId) return;

    // remove socket id from user's set
    if (activeUsers.has(currentUserId)) {
      activeUsers.get(currentUserId).delete(socket.id);
      if (activeUsers.get(currentUserId).size === 0) activeUsers.delete(currentUserId);
    }
    socketUser.delete(socket.id);

    // if user fully disconnected (no sockets), update lastSeen and notify followers/contacts
    try {
      if (!activeUsers.has(currentUserId)) {
        const user = await User.findByIdAndUpdate(currentUserId, { lastSeen: new Date() }, { new: true }).populate('following', '_id');
        if (user) {
          user.following.forEach(contact => {
            const cid = contact._id.toString();
            if (activeUsers.has(cid)) {
              [...activeUsers.get(cid)].forEach(sid => {
                io.to(sid).emit('userStatus', {
                  userId: currentUserId,
                  isOnline: false,
                  lastSeen: user.lastSeen
                });
              });
            }
          });
        }
      }
    } catch (err) {
      console.error('Disconnect error:', err);
    }
  });
});

// --------------------
// Start server
// --------------------
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
