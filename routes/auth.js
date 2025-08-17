const express = require('express');
const router = express.Router();
const User = require('../models/User');

// Register route
router.get('/register', (req, res) => {
    res.render('register');
});

router.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const user = new User({ username, email, password });
        await user.save();
        req.session.userId = user._id;
        res.redirect('/chat');
    } catch (error) {
        res.render('register', { error: error.message });
    }
});

// Login route
router.get('/login', (req, res) => {
    res.render('login');
});

router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        
        if (!user || !(await user.comparePassword(password))) {
            throw new Error('Invalid email or password');
        }
        
        req.session.userId = user._id;
        res.redirect('/chat');
    } catch (error) {
        res.render('login', { error: error.message });
    }
});

// Logout route
router.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

module.exports = router;
