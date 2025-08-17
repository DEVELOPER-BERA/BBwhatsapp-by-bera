module.exports = function(io) {
    io.on('connection', (socket) => {
        console.log('New user connected');
        
        // Join chat room
        socket.on('join', (username) => {
            socket.username = username;
            socket.broadcast.emit('message', {
                username: 'System',
                text: `${username} has joined the chat`,
                timestamp: new Date()
            });
        });
        
        // Handle chat messages
        socket.on('chatMessage', (msg) => {
            io.emit('message', {
                username: socket.username,
                text: msg,
                timestamp: new Date()
            });
        });
        
        // Handle disconnection
        socket.on('disconnect', () => {
            if (socket.username) {
                io.emit('message', {
                    username: 'System',
                    text: `${socket.username} has left the chat`,
                    timestamp: new Date()
                });
            }
        });
    });
};
