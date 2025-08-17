document.addEventListener('DOMContentLoaded', () => {
  const socket = io();

  // ===== DOM
  const chatMessages = document.getElementById('chat-messages');
  const chatForm = document.getElementById('chat-form');
  const messageInput = document.getElementById('msg');
  const typingBar = document.getElementById('typing-bar'); // optional
  const uploadInput = document.getElementById('media');    // optional <input type="file" id="media">

  // ===== App vars from EJS
  const { userId, username, conversationId, isGroup } = window.APP || {};

  // ===== Helpers
  const appendMessage = (m) => {
    const div = document.createElement('div');
    div.classList.add('message');
    const fromSelf = (m.sender?._id === userId) || (m.username === username);
    if (fromSelf) div.classList.add('own-message');
    if (m.deleted) div.classList.add('deleted');

    // sender name + time
    const displayName = m.sender?.username || m.username || 'User';
    const ts = new Date(m.createdAt || m.timestamp || Date.now()).toLocaleTimeString();

    let text = m.text || '';
    if (m.linkPreview?.title) {
      text += `<div class="link-preview">
        <div class="lp-domain">${m.linkPreview.domain || ''}</div>
        <div class="lp-title">${m.linkPreview.title || ''}</div>
        <div class="lp-desc">${m.linkPreview.description || ''}</div>
      </div>`;
    }

    // media render (basic)
    let mediaHtml = '';
    if (m.media?.url) {
      if (m.media.type === 'image') {
        mediaHtml = `<img class="msg-img" src="${m.media.url}" alt="image" />`;
      } else if (m.media.type === 'video') {
        mediaHtml = `<video class="msg-video" src="${m.media.url}" controls></video>`;
      } else if (m.media.type === 'audio') {
        mediaHtml = `<audio class="msg-audio" src="${m.media.url}" controls></audio>`;
      }
    }

    div.innerHTML = `
      <p class="meta">${displayName} <span>${ts}</span></p>
      <p class="text">${text}</p>
      ${mediaHtml}
    `;
    chatMessages.appendChild(div);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  };

  // ===== Join app + conversation
  socket.emit('join', userId);
  if (!isGroup && conversationId) {
    socket.emit('joinConversation', conversationId);
  }

  // ===== Incoming events
  socket.on('message', (m) => appendMessage(m));
  socket.on('messageUpdated', (m) => {
    // For simplicity, append updates as separate line (or diff if you track ids in DOM)
    appendMessage(m);
  });

  socket.on('newMessageNotification', (payload) => {
    // You can surface a toast/notification here:
    // payload = { conversationId, message }
    // e.g., show a bell icon or badge.
    // console.log('New message notification:', payload);
  });

  socket.on('typing', ({ conversationId: convId, typingUsers }) => {
    if (!typingBar) return;
    const names = (typingUsers || []).filter(id => id !== userId);
    typingBar.textContent = names.length ? 'Typing…' : '';
  });

  socket.on('userStatus', ({ userId: uid, isOnline, lastSeen }) => {
    // Update UI indicators for contacts
    // console.log('User status', uid, isOnline, lastSeen);
  });

  socket.on('messagesRead', ({ conversationId: convId, readerId }) => {
    // Update ticks/badges in UI if desired
    // console.log('Messages read in', convId, 'by', readerId);
  });

  // ===== Send message (text only or with uploaded media)
  chatForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = (messageInput?.value || '').trim();
    if (!text && !(uploadInput && uploadInput.files.length)) return;

    let media = null;
    if (uploadInput && uploadInput.files.length) {
      const file = uploadInput.files[0];
      const formData = new FormData();
      formData.append('media', file);
      const res = await fetch('/upload', { method: 'POST', body: formData });
      const data = await res.json();
      if (data?.url) {
        media = { url: data.url, type: data.type }; // type: image|video|audio
      }
      uploadInput.value = '';
    }

    socket.emit('chatMessage', {
      conversationId: isGroup ? null : conversationId,
      text,
      media
      // replyTo: { id: 'originalMessageId' }  // if you implement reply UI
    });

    if (messageInput) {
      messageInput.value = '';
      messageInput.focus();
    }
  });

  // ===== Typing indicator
  let typingTimer;
  const TYPING_DEBOUNCE = 1000;

  const startTyping = () => {
    if (!conversationId) return;
    socket.emit('typing', { conversationId, isTyping: true });
    clearTimeout(typingTimer);
    typingTimer = setTimeout(() => {
      socket.emit('typing', { conversationId, isTyping: false });
    }, TYPING_DEBOUNCE);
  };

  messageInput?.addEventListener('input', startTyping);

  // ===== Optional helpers for edit/delete/reaction
  window.editMessage = (messageId, newText) => {
    socket.emit('editMessage', { messageId, newText });
  };

  window.deleteMessage = (messageId) => {
    socket.emit('deleteMessage', { messageId });
  };

  window.reactToMessage = (messageId, icon) => {
    socket.emit('reactToMessage', { messageId, icon }); // icon like "👍"
  };
});
