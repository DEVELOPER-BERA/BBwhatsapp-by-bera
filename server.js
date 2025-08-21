import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import { createServer } from 'http';
import { Server } from 'socket.io';
import dotenv from 'dotenv';
dotenv.config();

const app = express();
const server = createServer(app);

// Database Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log(err));

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));
app.use(express.json());

// Models
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  online: Boolean
}));

// API Routes
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  
  try {
    const user = await User.create({ 
      username, 
      password: hashedPassword,
      online: false 
    });
    res.status(201).json({ userId: user._id });
  } catch (error) {
    res.status(400).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
    await User.updateOne({ _id: user._id }, { online: true });
    res.json({ token, userId: user._id });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// WebSocket Setup
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL,
    methods: ["GET", "POST"]
  }
});

const onlineUsers = new Map();

io.on('connection', (socket) => {
  console.log('New client connected');

  socket.on('authenticate', (userId) => {
    onlineUsers.set(userId, socket.id);
    io.emit('presence', { userId, online: true });
  });

  socket.on('message', ({ sender, recipient, content }) => {
    const recipientSocket = onlineUsers.get(recipient);
    if (recipientSocket) {
      io.to(recipientSocket).emit('message', { sender, content });
    }
  });

  socket.on('disconnect', () => {
    for (let [userId, sockId] of onlineUsers) {
      if (sockId === socket.id) {
        onlineUsers.delete(userId);
        io.emit('presence', { userId, online: false });
        break;
      }
    }
  });
});

server.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});
