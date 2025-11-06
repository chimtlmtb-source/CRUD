// src/controllers/authController.js
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import dotenv from 'dotenv';
import User from '../models/userModel.js';
import { sendResetEmail } from '../utils/email.js';

dotenv.config();

const ACCESS_TOKEN_EXP = '15m';
const REFRESH_TOKEN_DAYS = parseInt(process.env.REFRESH_TOKEN_DAYS || '7', 10);

const generateTokenString = (size = 64) =>
  crypto.randomBytes(size).toString('hex');

const createAccessToken = (user) =>
  jwt.sign(
    { userId: user._id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXP },
  );

const createRefreshTokenForUser = async (user, ip, familyId = null) => {
  const plainToken = generateTokenString(64);
  const tokenHash = await bcrypt.hash(plainToken, 10);
  const family = familyId || crypto.randomBytes(16).toString('hex');
  const expiresAt = new Date(
    Date.now() + REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000,
  );

  user.refreshTokens.push({
    tokenHash,
    familyId: family,
    createdByIp: ip,
    expiresAt,
  });

  await user.save();
  return { plainToken, familyId: family, expiresAt };
};

export const signup = async (req, res) => {
  try {
    const { name, email, password, age, role } = req.body;

    const existing = await User.findOne({ email });
    if (existing)
      return res.status(400).json({ message: 'Email already exists' });

    const hashed = await bcrypt.hash(password, 10);
    const verifyToken = crypto.randomBytes(32).toString('hex');

    const user = await User.create({
      name,
      email,
      password: hashed,
      age,
      role: role || 'BUYER',
      verifyToken,
    });

    const verifyLink = `${process.env.BASE_URL}/api/auth/verify/${verifyToken}`;
    console.log(` [Demo Verify Link]: ${verifyLink}`);

    res.status(201).json({
      message: 'User created. Check email for verification link.',
      verifyLink,
    });
  } catch (err) {
    console.error(' Signup error:', err);
    res.status(500).json({ message: err.message });
  }
};

export const verifyAccount = async (req, res) => {
  try {
    const user = await User.findOne({ verifyToken: req.params.token });
    if (!user)
      return res.status(400).json({ message: 'Invalid verification token' });

    user.isVerified = true;
    user.verifyToken = null;
    await user.save();

    res.json({ message: 'Account verified successfully' });
  } catch (err) {
    console.error(' Verify error:', err);
    res.status(500).json({ message: err.message });
  }
};

export const signin = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(400).json({ message: 'Invalid email or password' });

    if (!user.isVerified)
      return res
        .status(403)
        .json({ message: 'Please verify your email before logging in.' });

    const accessToken = createAccessToken(user);
    const { plainToken: refreshToken } = await createRefreshTokenForUser(
      user,
      req.ip,
    );

    res.json({
      accessToken,
      refreshToken,
      user: { id: user._id, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error('❌ Signin error:', err);
    res.status(500).json({ message: err.message });
  }
};

export const refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken)
      return res.status(400).json({ message: 'No refresh token' });

    const users = await User.find({ 'refreshTokens.revoked': false });
    let foundUser = null;
    let matched = null;

    for (const user of users) {
      for (const token of user.refreshTokens) {
        if (await bcrypt.compare(refreshToken, token.tokenHash)) {
          foundUser = user;
          matched = token;
          break;
        }
      }
      if (matched) break;
    }

    if (!matched)
      return res.status(401).json({ message: 'Invalid refresh token' });

    const accessToken = createAccessToken(foundUser);
    res.json({ accessToken });
  } catch (err) {
    console.error('Refresh error:', err);
    res.status(500).json({ message: err.message });
  }
};

export const logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const users = await User.find({ 'refreshTokens.revoked': false });
    let foundUser = null;

    for (const user of users) {
      for (const t of user.refreshTokens) {
        if (await bcrypt.compare(refreshToken, t.tokenHash)) {
          t.revoked = true;
          foundUser = user;
          break;
        }
      }
      if (foundUser) break;
    }

    if (!foundUser) return res.status(400).json({ message: 'Invalid token' });

    await foundUser.save();
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ message: err.message });
  }
};

export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Email not found' });

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetToken = resetToken;
    user.resetTokenExpire = Date.now() + 3600000; // 1h
    await user.save();

    const resetLink = `${process.env.BASE_URL}/api/auth/reset/${resetToken}`;
    console.log(` [Demo Reset Link]: ${resetLink}`);
    await sendResetEmail(email, resetLink);

    res.json({ message: 'Password reset link sent to email' });
  } catch (err) {
    console.error(' Forgot password error:', err);
    res.status(500).json({ message: err.message });
  }
};

export const resetPassword = async (req, res) => {
  try {
    const user = await User.findOne({
      resetToken: req.params.token,
      resetTokenExpire: { $gt: Date.now() },
    });

    if (!user)
      return res
        .status(400)
        .json({ message: 'Invalid or expired reset token' });

    const hashed = await bcrypt.hash(req.body.password, 10);
    user.password = hashed;
    user.resetToken = null;
    user.resetTokenExpire = null;
    await user.save();

    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ message: err.message });
  }
};
