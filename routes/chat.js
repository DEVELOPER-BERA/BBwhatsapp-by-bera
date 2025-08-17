const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { isAuthenticated } = require('../middleware/auth');

router.get('/chat', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        res.render('chat', { username: user.username });
    } catch (error) {
        res.redirect('/login');
    }
});

module.exports = router;
