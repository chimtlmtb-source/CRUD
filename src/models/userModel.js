import mongoose from 'mongoose';
import validator from 'validator';

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      validate: [validator.isEmail, 'Invalid email'],
    },
    password: { type: String, required: true, minlength: 6 },
    age: { type: Number, required: true },
    role: {
      type: String,
      enum: ['ADMIN', 'SELLER', 'BUYER'],
      default: 'BUYER',
    },
    isVerified: { type: Boolean, default: false },
  },
  { timestamps: true },
);

export default mongoose.model('User', userSchema);
