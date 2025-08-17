const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  id: {
    type: String,
    required: true,
    unique: true
  },
  conversation: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Conversation'
  },
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  text: {
    type: String,
    trim: true
  },
  type: {
    type: String,
    enum: ['private', 'chat', 'system'],
    default: 'private'
  },
  replyTo: {
    messageId: String,
    senderId: mongoose.Schema.Types.ObjectId,
    text: String
  },
  media: {
    url: String,
    type: String
  },
  linkPreview: {
    url: String,
    title: String,
    description: String,
    image: String,
    domain: String
  },
  reactions: {
    type: Map,
    of: [mongoose.Schema.Types.ObjectId]
  },
  read: {
    type: Boolean,
    default: false
  },
  readBy: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  pinned: {
    type: Boolean,
    default: false
  },
  edited: {
    type: Boolean,
    default: false
  },
  deleted: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Add index for better performance
messageSchema.index({ conversation: 1, createdAt: -1 });
messageSchema.index({ sender: 1 });
messageSchema.index({ type: 1, createdAt: -1 });

module.exports = mongoose.model('Message', messageSchema);
