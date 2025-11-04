const User = require('../models/userModel');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { sendResetEmail } = require('../utils/email');

const ACCESS_TOKEN_EXP = '15m'; // access token life
const REFRESH_TOKEN_DAYS = process.env.REFRESH_TOKEN_DAYS
  ? parseInt(process.env.REFRESH_TOKEN_DAYS, 10)
  : 7;

// helper: generate random token (plain) — we will hash before storing
const generateTokenString = (size = 64) =>
  crypto.randomBytes(size).toString('hex');

// helper: create access token (JWT)
const createAccessToken = (user) => {
  return jwt.sign(
    { userId: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXP },
  );
};

// helper: create refresh token entry and return plain token to client
const createRefreshTokenForUser = async (user, ipAddress, familyId = null) => {
  const plainToken = generateTokenString(64);
  const tokenHash = await bcrypt.hash(plainToken, 10);
  const family = familyId || crypto.randomBytes(16).toString('hex'); // family id
  const expiresAt = new Date(
    Date.now() + REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000,
  );

  // push token subdoc
  user.refreshTokens.push({
    tokenHash,
    familyId: family,
    createdByIp: ipAddress,
    expiresAt,
  });

  // keep DB small: remove expired tokens older than some threshold (optional)
  // but we'll not auto-remove here to preserve audit trail

  await user.save();

  return { plainToken, familyId: family, expiresAt };
};

// helper: find refresh token doc by comparing hashes (iterate user's tokens)
const findTokenDocByPlain = async (user, plainToken) => {
  if (!user || !user.refreshTokens) return null;
  // compare sequentially (bcrypt compare)
  for (let i = 0; i < user.refreshTokens.length; i++) {
    const t = user.refreshTokens[i];
    // skip already expired
    if (t.expiresAt && t.expiresAt < Date.now()) continue;
    const match = await bcrypt.compare(plainToken, t.tokenHash);
    if (match) {
      // return token doc + index (so we can update)
      return { tokenDoc: t, index: i };
    }
  }
  return null;
};

// revoke all tokens in a family (mark revoked)
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

// 🔹 SIGNUP (unchanged except minor)
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
        'Dang ky thanh cong. Vui long kiem tra email de xac minh tai khoan.',
      verifyUrl,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
};

// 🔹 VERIFY ACCOUNT (unchanged)
const verifyAccount = async (req, res) => {
  try {
    const { token } = req.params;
    let decoded;

    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res
        .status(400)
        .json({ message: 'Invalid or expired verify token' });
    }

    const user = await User.findOne({ email: decoded.email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (user.isVerified)
      return res.status(400).json({ message: 'Account already verified' });

    user.isVerified = true;
    user.verifyToken = null;
    await user.save();

    res.json({ message: 'Tai khoan duoc xac minh thanh cong' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// 🔹 SIGNIN (returns access + refresh)
const signin = async (req, res) => {
  try {
    const { email, password } = req.body;
    const ipAddress = req.ip || req.connection?.remoteAddress || null;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    if (!user.isVerified)
      return res.status(403).json({ message: 'Account not verified yet' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: 'Invalid credentials' });

    const accessToken = createAccessToken(user);

    // create refresh token and save hashed to DB (new family created)
    const {
      plainToken: refreshToken,
      familyId,
      expiresAt,
    } = await createRefreshTokenForUser(user, ipAddress, null);

    // return tokens
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

// 🔹 REFRESH endpoint: accept refreshToken, create new accessToken + rotate refresh token
const refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const ipAddress = req.ip || req.connection?.remoteAddress || null;

    if (!refreshToken)
      return res.status(400).json({ message: 'Refresh token is required' });

    // Find user that has this token (we need to search users)
    // Efficient approach: query all users with any refreshToken — Mongo can't bcrypt-compare, so fetch by email?
    // But we only have token; we'll search by scanning users (for demo/local). For production use separate store (Redis) or store token id.
    // Here we search user collection and check tokens for match.
    const users = await User.find({}); // NOTE: for large scale, change strategy
    let matchedUser = null;
    let matched = null;
    for (let u of users) {
      const found = await findTokenDocByPlain(u, refreshToken);
      if (found) {
        matchedUser = u;
        matched = found; // { tokenDoc, index }
        break;
      }
    }

    if (!matchedUser || !matched) {
      // token not found -> possible reuse attempt; since we can't map family we will respond 401
      return res.status(401).json({ message: 'Refresh token invalid' });
    }

    const tokenDoc = matched.tokenDoc;
    const tokenIndex = matched.index;

    // check expiration
    if (tokenDoc.expiresAt && tokenDoc.expiresAt < Date.now()) {
      return res.status(400).json({ message: 'Refresh token expired' });
    }

    // If token already revoked => reuse detected -> revoke whole family
    if (tokenDoc.revoked) {
      // revoke the whole family
      await revokeTokenFamily(matchedUser, tokenDoc.familyId, ipAddress);
      return res
        .status(401)
        .json({ message: 'Refresh token reuse detected. All tokens revoked.' });
    }

    // Good token: rotate -> mark current token revoked + create new refresh token with same familyId
    // mark current token revoked and set replacedByToken (we won't keep plain replaced token)
    matchedUser.refreshTokens[tokenIndex].revoked = true;
    matchedUser.refreshTokens[tokenIndex].revokedAt = new Date();
    matchedUser.refreshTokens[tokenIndex].revokedByIp = ipAddress;

    // create new refresh token in same family
    const { plainToken: newRefreshToken, expiresAt } =
      await createRefreshTokenForUser(
        matchedUser,
        ipAddress,
        tokenDoc.familyId,
      );

    // create new access token
    const accessToken = createAccessToken(matchedUser);

    res.json({
      accessToken,
      refreshToken: newRefreshToken,
      refreshTokenExpiresAt: expiresAt,
      expiresIn: ACCESS_TOKEN_EXP,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err.message });
  }
};

// 🔹 LOGOUT: revoke the refresh token provided (or entire family)
const logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const ipAddress = req.ip || req.connection?.remoteAddress || null;
    if (!refreshToken)
      return res.status(400).json({ message: 'Refresh token is required' });

    const users = await User.find({});
    let matchedUser = null;
    let matched = null;
    for (let u of users) {
      const found = await findTokenDocByPlain(u, refreshToken);
      if (found) {
        matchedUser = u;
        matched = found;
        break;
      }
    }
    if (!matchedUser) return res.status(200).json({ message: 'Logged out' });

    const tokenDoc = matched.tokenDoc;
    const tokenIndex = matched.index;

    // revoke this token
    matchedUser.refreshTokens[tokenIndex].revoked = true;
    matchedUser.refreshTokens[tokenIndex].revokedAt = new Date();
    matchedUser.refreshTokens[tokenIndex].revokedByIp = ipAddress;
    await matchedUser.save();

    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// 🔹 FORGOT PASSWORD (unchanged)
const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const shortToken = jwt.sign(
      { userId: user._id },
      process.env.SHORT_TOKEN_SECRET,
      { expiresIn: process.env.SHORT_TOKEN_EXPIRY },
    );

    user.resetToken = shortToken;
    user.resetTokenExpire = Date.now() + 15 * 60 * 1000;
    await user.save();

    const resetLink = `http://localhost:${process.env.PORT}/api/auth/reset/${shortToken}`;
    sendResetEmail(email, resetLink);

    res.json({
      message: 'Link dat lai mat khau da duoc log (demo)',
      resetLink,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// 🔹 RESET PASSWORD (unchanged)
const resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.SHORT_TOKEN_SECRET);
    } catch (err) {
      if (err.name === 'TokenExpiredError')
        return res.status(400).json({ message: 'Short token expired' });
      return res.status(400).json({ message: 'Invalid short token' });
    }

    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (user.resetToken !== token || user.resetTokenExpire < Date.now())
      return res
        .status(400)
        .json({ message: 'Short token invalid or expired' });

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
  forgotPassword,
  resetPassword,
  refresh,
  logout,
};
