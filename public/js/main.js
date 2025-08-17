// Global socket connection
const socket = io();

// Initialize tooltips
document.addEventListener('DOMContentLoaded', () => {
    // Initialize any tooltips or UI elements
    initializeTooltips();
    
    // Handle media preview modals
    setupMediaPreviews();
});

function initializeTooltips() {
    // Initialize any tooltip libraries or custom tooltips
    const tooltipTriggers = document.querySelectorAll('[data-tooltip]');
    
    tooltipTriggers.forEach(trigger => {
        trigger.addEventListener('mouseenter', showTooltip);
        trigger.addEventListener('mouseleave', hideTooltip);
    });
}

function showTooltip(e) {
    const tooltipText = this.getAttribute('data-tooltip');
    const tooltip = document.createElement('div');
    tooltip.className = 'tooltip';
    tooltip.textContent = tooltipText;
    
    document.body.appendChild(tooltip);
    
    const rect = this.getBoundingClientRect();
    tooltip.style.left = `${rect.left + rect.width / 2 - tooltip.offsetWidth / 2}px`;
    tooltip.style.top = `${rect.top - tooltip.offsetHeight - 5}px`;
}

function hideTooltip() {
    const tooltip = document.querySelector('.tooltip');
    if (tooltip) {
        tooltip.remove();
    }
}

function setupMediaPreviews() {
    // Handle clicks on media thumbnails
    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('media-thumbnail')) {
            e.preventDefault();
            showMediaModal(e.target.src || e.target.querySelector('source').src);
        }
    });
}

function showMediaModal(mediaUrl) {
    const modal = document.createElement('div');
    modal.className = 'media-modal';
    
    const mediaType = mediaUrl.match(/\.(jpeg|jpg|gif|png)$/) ? 'image' : 
                     mediaUrl.match(/\.(mp4|webm|ogg)$/) ? 'video' : 'audio';
    
    let mediaElement;
    if (mediaType === 'image') {
        mediaElement = document.createElement('img');
        mediaElement.src = mediaUrl;
    } else if (mediaType === 'video') {
        mediaElement = document.createElement('video');
        mediaElement.controls = true;
        const source = document.createElement('source');
        source.src = mediaUrl;
        source.type = `video/${mediaUrl.split('.').pop()}`;
        mediaElement.appendChild(source);
    } else {
        mediaElement = document.createElement('audio');
        mediaElement.controls = true;
        const source = document.createElement('source');
        source.src = mediaUrl;
        source.type = `audio/${mediaUrl.split('.').pop()}`;
        mediaElement.appendChild(source);
    }
    
    mediaElement.className = 'modal-media';
    
    const closeBtn = document.createElement('button');
    closeBtn.className = 'close-modal';
    closeBtn.innerHTML = '&times;';
    closeBtn.addEventListener('click', () => modal.remove());
    
    const downloadBtn = document.createElement('a');
    downloadBtn.className = 'download-media';
    downloadBtn.href = mediaUrl;
    downloadBtn.download = mediaUrl.split('/').pop();
    downloadBtn.innerHTML = '<i class="fas fa-download"></i>';
    
    modal.appendChild(mediaElement);
    modal.appendChild(closeBtn);
    modal.appendChild(downloadBtn);
    
    document.body.appendChild(modal);
}

// Handle private message encryption/decryption
function encryptMessage(text) {
    // In a real app, this would use proper end-to-end encryption
    // This is just a placeholder implementation
    return btoa(encodeURIComponent(text));
}

function decryptMessage(encrypted) {
    // In a real app, this would use proper end-to-end encryption
    // This is just a placeholder implementation
    return decodeURIComponent(atob(encrypted));
}

// Handle online status updates
socket.on('userOnline', (userId) => {
    const statusElement = document.querySelector(`[data-user-id="${userId}"] .status`);
    if (statusElement) {
        statusElement.innerHTML = '<span class="online-dot"></span> Online';
    }
});

socket.on('userOffline', (userId, lastSeen) => {
    const statusElement = document.querySelector(`[data-user-id="${userId}"] .status`);
    if (statusElement) {
        statusElement.textContent = `Last seen ${new Date(lastSeen).toLocaleTimeString()}`;
    }
});

// Handle notifications
function showNotification(title, message) {
    if (Notification.permission === 'granted') {
        new Notification(title, { body: message });
    } else if (Notification.permission !== 'denied') {
        Notification.requestPermission().then(permission => {
            if (permission === 'granted') {
                new Notification(title, { body: message });
            }
        });
    }
}

// Handle service worker registration for PWA
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js').then(registration => {
            console.log('ServiceWorker registration successful');
        }).catch(err => {
            console.log('ServiceWorker registration failed: ', err);
        });
    });
      }
