document.addEventListener('DOMContentLoaded', () => {
  const socket = io();
  const chatMessages = document.getElementById('chat-messages');
  const chatForm = document.getElementById('chat-form');
  const messageInput = document.getElementById('msg');
  const typingIndicator = document.getElementById('typing-indicator');
  
  // Get current user from session
  const currentUser = JSON.parse(localStorage.getItem('currentUser'));
  if (!currentUser) return window.location.href = '/login';

  // Authenticate socket
  socket.emit('authenticate', currentUser.id);

  // Join conversation
  const urlParams = new URLSearchParams(window.location.search);
  const conversationId = urlParams.get('conversation');
  if (conversationId) {
    socket.emit('joinConversation', conversationId);
  }

  // Socket events
  socket.on('newMessage', (message) => {
    appendMessage(message);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  });

  socket.on('userStatus', (data) => {
    updateUserStatus(data);
  });

  socket.on('typing', (data) => {
    showTypingIndicator(data);
  });

  socket.on('error', (message) => {
    showError(message);
  });

  // Message submission
  chatForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const message = messageInput.value.trim();
    if (!message) return;

    socket.emit('sendMessage', {
      conversationId,
      text: message
    });

    messageInput.value = '';
  });

  // Typing indicators
  messageInput.addEventListener('input', () => {
    socket.emit('typing', {
      conversationId,
      isTyping: true
    });

    clearTimeout(window.typingTimeout);
    window.typingTimeout = setTimeout(() => {
      socket.emit('typing', {
        conversationId,
        isTyping: false
      });
    }, 2000);
  });

  // Helper functions
  function appendMessage(message) {
    const div = document.createElement('div');
    div.classList.add('message');
    
    if (message.sender._id === currentUser.id) {
      div.classList.add('own-message');
    }

    div.innerHTML = `
      <p class="meta">${message.sender.username} 
        <span>${new Date(message.timestamp).toLocaleTimeString()}</span>
      </p>
      <p class="text">${message.text}</p>
    `;
    chatMessages.appendChild(div);
  }

  function showTypingIndicator(data) {
    if (data.userId === currentUser.id) return;
    
    typingIndicator.textContent = data.isTyping 
      ? `${data.username} is typing...` 
      : '';
  }
});

// Add this to your login success handler:
localStorage.setItem('currentUser', JSON.stringify(user));
