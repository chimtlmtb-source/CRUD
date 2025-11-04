const mongoose = require('mongoose');
const validator = require('validator');

const refreshTokenSchema = new mongoose.Schema({
  tokenHash: { type: String, required: true }, // hashed refresh token
  familyId: { type: String, required: true }, // token family id
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
  revoked: { type: Boolean, default: false },
  replacedByToken: { type: String, default: null }, // optional: store token id or plain token (we'll store null)
  createdByIp: { type: String, default: null },
  revokedAt: { type: Date, default: null },
  revokedByIp: { type: String, default: null },
});

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Name is required'],
      trim: true,
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      trim: true,
      lowercase: true,
      validate: {
        validator: (value) => validator.isEmail(value),
        message: 'Invalid email format',
      },
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [6, 'Password must be at least 6 characters'],
    },
    age: {
      type: Number,
      required: [true, 'Age is required'],
      min: [0, 'Age must be >= 0'],
    },

    isVerified: {
      type: Boolean,
      default: false,
    },
    verifyToken: {
      type: String,
      default: null,
    },

    resetToken: {
      type: String,
      default: null,
    },
    resetTokenExpire: {
      type: Date,
      default: null,
    },

    // refresh tokens stored as subdocuments (hashed)
    refreshTokens: {
      type: [refreshTokenSchema],
      default: [],
    },
  },
  { timestamps: true },
);

module.exports = mongoose.model('User', userSchema);
