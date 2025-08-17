const mongoose = require('mongoose');

const FollowSchema = new mongoose.Schema({
  follower: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  followee: {
    type: mongoose.Schema.Types.ObjectId,
    refPath: 'followeeModel',
    required: true
  },
  followeeModel: {
    type: String,
    required: true,
    enum: ['User', 'Chatroom']
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Ensure one follow relationship per pair
FollowSchema.index({ follower: 1, followee: 1 }, { unique: true });

module.exports = mongoose.model('Follow', FollowSchema);
