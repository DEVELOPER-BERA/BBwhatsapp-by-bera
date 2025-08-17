// socket/chat.js
const moment = require("moment");

let users = {}; // socket.id -> username
let groups = ["Developers", "Friends", "Family"]; // default groups
let messages = []; // global messages only (for now)

function chatHandler(io) {
  io.on("connection", (socket) => {
    console.log("⚡ New socket connected:", socket.id);

    // Join with username
    socket.on("join", (username) => {
      users[socket.id] = username;
      console.log(`${username} joined`);

      // Send current users to everyone
      io.emit("users", Object.values(users));

      // Send join message to global
      const joinMsg = {
        username: "System",
        text: `${username} has joined the chat`,
        timestamp: Date.now()
      };
      messages.push(joinMsg);
      io.emit("message", joinMsg);
    });

    // Global message
    socket.on("chatMessage", (msg) => {
      const newMsg = {
        username: msg.username,
        text: msg.text,
        timestamp: Date.now()
      };
      messages.push(newMsg);
      io.emit("message", newMsg);
    });

    // Private message
    socket.on("privateMessage", ({ to, text }) => {
      const fromUser = users[socket.id];
      const msg = {
        from: fromUser,
        to,
        text,
        timestamp: Date.now()
      };

      // Find socket ID for recipient
      const targetSocketId = Object.keys(users).find(
        (id) => users[id] === to
      );
      if (targetSocketId) {
        io.to(targetSocketId).emit("privateMessage", msg);
        socket.emit("privateMessage", msg); // also show in sender’s chat
      }
    });

    // Join a group
    socket.on("joinRoom", (room) => {
      socket.join(room);
      socket.emit("message", {
        username: "System",
        text: `You joined group ${room}`,
        timestamp: Date.now()
      });
      socket.to(room).emit("message", {
        username: "System",
        text: `${users[socket.id]} joined group ${room}`,
        timestamp: Date.now()
      });
    });

    // Disconnect
    socket.on("disconnect", () => {
      const username = users[socket.id];
      delete users[socket.id];
      io.emit("users", Object.values(users));
      io.emit("message", {
        username: "System",
        text: `${username} has left the chat`,
        timestamp: Date.now()
      });
    });
  });
}

module.exports = { chatHandler, users, groups, messages };
