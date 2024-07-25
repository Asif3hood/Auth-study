const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const createError = require('../utils/appError');

// Convert the secret key from hex to a Buffer
const secretKey = Buffer.from("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 'hex');

const decryptData = (encryptedData, ivBase64) => {
    try {
      const iv = Buffer.from(ivBase64, 'base64');
      const encryptedText = Buffer.from(encryptedData, 'base64');
      const decipher = crypto.createDecipheriv('aes-256-cbc', secretKey, iv);
      decipher.setAutoPadding(true);
      let decrypted = decipher.update(encryptedText);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      return JSON.parse(decrypted.toString());
    } catch (error) {
      console.error('Decryption error:', error);
      throw new Error('Decryption failed: ' + error.message);
    }
  };

// REGISTER USER
exports.signup = async (req, res, next) => {
  try {
   const { data: encryptedData, iv } = req.body;
    const { name, email, password, passwordConfirm } = decryptData(encryptedData, iv);
    if (password !== passwordConfirm) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return next(new createError('User already registered!', 400));
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const newUser = await User.create({
      name,
      email,
      password: hashedPassword,
    });

    const token = jwt.sign({ _id: newUser._id }, "your-jwt-secret", { expiresIn: '90d' });

    res.status(201).json({
      status: 'success',
      message: 'User registered successfully',
      token,
      user: {
        _id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
      },
    });
  } catch (error) {
    next(error);
  }
};

// LOGIN USER
exports.login = async (req, res, next) => {
  try {
    const { data: encryptedData, iv } = req.body;
    const { email, password } = decryptData(encryptedData, iv);

    console.log(req.body);
    console.log(decryptData(encryptedData, iv));

    const user = await User.findOne({ email }).select('+password');
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign({ _id: user._id }, "your-jwt-secret", { expiresIn: '90d' });

    res.status(200).json({
      status: 'success',
      token,
      message: 'Logged in successfully',
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    next(error);
  }
};
