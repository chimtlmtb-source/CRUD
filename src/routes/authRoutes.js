// src/routes/authRoutes.js
import express from 'express';
import {
  signup,
  verifyAccount,
  signin,
  refresh,
  logout,
  forgotPassword,
  resetPassword,
} from '../controllers/authController.js';

const router = express.Router();

router.post('/signup', signup);
router.get('/verify/:token', verifyAccount);
router.post('/signin', signin);
router.post('/refresh', refresh);
router.post('/logout', logout);
router.post('/forgot', forgotPassword);
router.post('/reset/:token', resetPassword);

export default router;
