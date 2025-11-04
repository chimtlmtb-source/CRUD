const express = require('express');
const router = express.Router();
const {
  signup,
  signin,
  verifyAccount,
  forgotPassword,
  resetPassword,
  refresh,
  logout,
} = require('../controllers/authController');

router.post('/signup', signup);
router.get('/verify/:token', verifyAccount);
router.post('/signin', signin);
router.post('/forgot', forgotPassword);
router.post('/reset/:token', resetPassword);

// NEW
router.post('/refresh', refresh);
router.post('/logout', logout);

module.exports = router;
