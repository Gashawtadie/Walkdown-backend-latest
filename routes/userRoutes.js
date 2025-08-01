const express = require("express");
const router = express.Router();
const {
  register,
  login,
  checkUser,
  requestOTP,
  resetPassword,
} = require("../controller/userController");

// Authentication middleware
const authMiddleware = require("../middleware/authMiddleware");

// Validation middleware
const {
  validateRegistration,
  validateLogin,
  validatePasswordReset,
  validateForgotPassword,
} = require("../middleware/validationMiddleware");

// register route
router.post("/register", validateRegistration, register);

// login user
router.post("/login", validateLogin, login);

// check user authentication
router.get("/check", authMiddleware, checkUser);

// route to request an otp for password reset
router.post("/forgot-password", validateForgotPassword, requestOTP);

// route to reset password using otp
router.post("/reset-password", validatePasswordReset, resetPassword);

module.exports = router;
