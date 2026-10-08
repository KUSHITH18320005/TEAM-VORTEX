const { Schema } = require("mongoose");

const UserSchema = new Schema({
  username: {
    type: String,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    default: "trader",
  },
  accountBalance: {
    type: Number,
    default: 100000.0,
  },
  resetToken: String,
  resetTokenExpiry: Date,
  failedLoginAttempts: {
    type: Number,
    default: 0,
  },
  lockUntil: Date,
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = { UserSchema };
