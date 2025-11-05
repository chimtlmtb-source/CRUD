const User = require('../models/userModel');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { sendResetEmail } = require('../utils/email');

// ========== CONFIG ==========
const ACCESS_TOKEN_EXP = '15m'; // access token TTL
const REFRESH_TOKEN_DAYS = parseInt(process.env.REFRESH_TOKEN_DAYS || '7', 10);

// ========== HELPERS ==========
const generateTokenString = (size = 64) =>
  crypto.randomBytes(size).toString('hex');

const createAccessToken = (user) =>
  jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_EXP,
  });

const createRefreshTokenForUser = async (user, ipAddress, familyId = null) => {
  const plainToken = generateTokenString(64);
  const tokenHash = await bcrypt.hash(plainToken, 10);
  const family = familyId || crypto.randomBytes(16).toString('hex');
  const expiresAt = new Date(
    Date.now() + REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000,
  );

  user.refreshTokens.push({
    tokenHash,
    familyId: family,
    createdByIp: ipAddress,
    expiresAt,
  });

  await user.save();

  return { plainToken, familyId: family, expiresAt };
};

const findTokenDocByPlain = async (user, plainToken) => {
  if (!user?.refreshTokens) return null;

  for (let i = 0; i < user.refreshTokens.length; i++) {
    const t = user.refreshTokens[i];
    if (t.expiresAt && t.expiresAt < Date.now()) continue;

    const match = await bcrypt.compare(plainToken, t.tokenHash);
    if (match) return { tokenDoc: t, index: i };
  }
  return null;
};

const revokeTokenFamily = async (user, familyId, ipAddress) => {
  let changed = false;
  user.refreshTokens.forEach((t) => {
    if (t.familyId === familyId && !t.revoked) {
      t.revoked = true;
      t.revokedAt = new Date();
      t.revokedByIp = ipAddress || null;
      changed = true;
    }
  });
  if (changed) await user.save();
};

// ========== AUTH CONTROLLER ==========

// SIGNUP
const signup = async (req, res) => {
  try {
    const { name, email, password, age } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: 'Email already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const verifyToken = jwt.sign({ email }, process.env.JWT_SECRET, {
      expiresIn: '1d',
    });

    const user = new User({
      name,
      email,
      password: hashedPassword,
      age,
      verifyToken,
    });
    await user.save();

    const verifyUrl = `http://localhost:${process.env.PORT}/api/auth/verify/${verifyToken}`;
    res.status(201).json({
      message:
        'Đăng ký thành công. Vui lòng kiểm tra email để xác minh tài khoản.',
      verifyUrl,
    });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
};

// VERIFY ACCOUNT
const verifyAccount = async (req, res) => {
  try {
    const decoded = jwt.verify(req.params.token, process.env.JWT_SECRET);
    const user = await User.findOne({ email: decoded.email });
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (user.isVerified)
      return res.status(400).json({ message: 'Already verified' });

    user.isVerified = true;
    user.verifyToken = null;
    await user.save();

    res.json({ message: 'Tài khoản đã được xác minh thành công!' });
  } catch (err) {
    res.status(400).json({ message: 'Token không hợp lệ hoặc đã hết hạn' });
  }
};

// SIGNIN
const signin = async (req, res) => {
  try {
    const { email, password } = req.body;
    const ipAddress = req.ip;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    if (!user.isVerified)
      return res.status(403).json({ message: 'Account not verified' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: 'Invalid credentials' });

    const accessToken = createAccessToken(user);
    const { plainToken: refreshToken, expiresAt } =
      await createRefreshTokenForUser(user, ipAddress);

    res.json({
      accessToken,
      refreshToken,
      expiresIn: ACCESS_TOKEN_EXP,
      refreshTokenExpiresAt: expiresAt,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// REFRESH TOKEN
const refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const ipAddress = req.ip;
    if (!refreshToken)
      return res.status(400).json({ message: 'Refresh token is required' });

    const users = await User.find({});
    let matchedUser = null;
    let matched = null;
    for (const u of users) {
      const found = await findTokenDocByPlain(u, refreshToken);
      if (found) {
        matchedUser = u;
        matched = found;
        break;
      }
    }

    if (!matchedUser)
      return res.status(401).json({ message: 'Invalid refresh token' });

    const { tokenDoc, index } = matched;
    if (tokenDoc.expiresAt < Date.now())
      return res.status(400).json({ message: 'Refresh token expired' });

    if (tokenDoc.revoked) {
      await revokeTokenFamily(matchedUser, tokenDoc.familyId, ipAddress);
      return res
        .status(401)
        .json({ message: 'Reuse detected. Tokens revoked.' });
    }

    matchedUser.refreshTokens[index].revoked = true;
    matchedUser.refreshTokens[index].revokedAt = new Date();
    matchedUser.refreshTokens[index].revokedByIp = ipAddress;

    const { plainToken: newRefreshToken, expiresAt } =
      await createRefreshTokenForUser(
        matchedUser,
        ipAddress,
        tokenDoc.familyId,
      );

    const newAccessToken = createAccessToken(matchedUser);
    res.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      refreshTokenExpiresAt: expiresAt,
      expiresIn: ACCESS_TOKEN_EXP,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// LOGOUT
const logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const ipAddress = req.ip;
    if (!refreshToken)
      return res.status(400).json({ message: 'Refresh token required' });

    const users = await User.find({});
    let matchedUser = null;
    let matched = null;
    for (const u of users) {
      const found = await findTokenDocByPlain(u, refreshToken);
      if (found) {
        matchedUser = u;
        matched = found;
        break;
      }
    }

    if (!matchedUser)
      return res.status(200).json({ message: 'Already logged out' });

    matchedUser.refreshTokens[matched.index].revoked = true;
    matchedUser.refreshTokens[matched.index].revokedAt = new Date();
    matchedUser.refreshTokens[matched.index].revokedByIp = ipAddress;
    await matchedUser.save();

    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// FORGOT PASSWORD (unchanged)
const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const shortToken = jwt.sign(
      { userId: user._id },
      process.env.SHORT_TOKEN_SECRET,
      {
        expiresIn: process.env.SHORT_TOKEN_EXPIRY,
      },
    );

    user.resetToken = shortToken;
    user.resetTokenExpire = Date.now() + 15 * 60 * 1000;
    await user.save();

    const resetLink = `http://localhost:${process.env.PORT}/api/auth/reset/${shortToken}`;
    sendResetEmail(email, resetLink);

    res.json({ message: 'Demo: reset link logged', resetLink });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// RESET PASSWORD (unchanged)
const resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    const decoded = jwt.verify(token, process.env.SHORT_TOKEN_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (user.resetToken !== token || user.resetTokenExpire < Date.now())
      return res.status(400).json({ message: 'Invalid or expired token' });

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    user.resetToken = null;
    user.resetTokenExpire = null;
    await user.save();

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

module.exports = {
  signup,
  verifyAccount,
  signin,
  refresh,
  logout,
  forgotPassword,
  resetPassword,
};
