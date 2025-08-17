module.exports = {
    isAuthenticated: (req, res, next) => {
        if (req.session.userId) {
            return next();
        }
        res.redirect('/login');
    },
    
    isGuest: (req, res, next) => {
        if (!req.session.userId) {
            return next();
        }
        res.redirect('/chat');
    }
};
