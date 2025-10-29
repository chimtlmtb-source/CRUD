const User = require('../models/userModel');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { sendResetEmail } = require('../utils/email');

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

// 🔹 VERIFY ACCOUNT
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

// 🔹 SIGNIN (JWT)
const signin = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    if (!user.isVerified)
      return res.status(403).json({ message: 'Account not verified yet' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// 🔹 FORGOT PASSWORD
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

// 🔹 RESET PASSWORD
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
};
