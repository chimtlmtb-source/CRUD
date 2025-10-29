const User = require('../models/userModel');
const bcrypt = require('bcryptjs');
// Lấy tất cả user
const getUsers = async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// Lấy 1 user theo id
const getUserById = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (err) {
    if (err.name === 'CastError')
      return res.status(400).json({ message: 'Invalid ID' });
    res.status(500).json({ message: err.message });
  }
};

// CREATE User
const createUser = async (req, res) => {
  try {
    const { name, email, password, age } = req.body;

    // ✅ Validate các trường
    if (!name || !email || !password || !age) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // ✅ Check email đã tồn tại chưa
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({ message: 'Email already exists. Please use another email.' });
    }

    // ✅ Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // ✅ Tạo user mới
    const newUser = new User({ name, email, password: hashedPassword, age });
    await newUser.save();

    res
      .status(201)
      .json({ message: 'User created successfully', user: newUser });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// UPDATE User
const updateUser = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email, age } = req.body;

    // ✅ Tìm user cần update
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // ✅ Nếu user đổi email -> kiểm tra email mới có trùng ai khác không
    if (email && email !== user.email) {
      const emailExists = await User.findOne({ email });
      if (emailExists) {
        return res.status(400).json({ message: 'Email already in use' });
      }
      user.email = email;
    }

    // ✅ Update các field còn lại
    if (name) user.name = name;
    if (age) user.age = age;

    await user.save();

    res.json({ message: 'User updated successfully', user });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// Xóa user
const deleteUser = async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'User deleted' });
  } catch (err) {
    if (err.name === 'CastError')
      return res.status(400).json({ message: 'Invalid ID' });
    res.status(500).json({ message: err.message });
  }
};

module.exports = { getUsers, getUserById, createUser, updateUser, deleteUser };
