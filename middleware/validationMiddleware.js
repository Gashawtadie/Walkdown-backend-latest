const { StatusCodes } = require("http-status-codes");

// Email validation regex
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Password validation - at least 6 characters
const passwordRegex = /^.{6,}$/;

// Username validation - alphanumeric and underscore, 3-20 characters
const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;

const validateRegistration = (req, res, next) => {
  const { username, firstname, lastname, email, password } = req.body;

  // Check if all required fields are present
  if (!username || !firstname || !lastname || !email || !password) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "All fields are required",
      missing: {
        username: !username,
        firstname: !firstname,
        lastname: !lastname,
        email: !email,
        password: !password
      }
    });
  }

  // Validate email format
  if (!emailRegex.test(email)) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "Invalid email format"
    });
  }

  // Validate password strength
  if (!passwordRegex.test(password)) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "Password must be at least 6 characters long"
    });
  }

  // Validate username format
  if (!usernameRegex.test(username)) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "Username must be 3-20 characters long and contain only letters, numbers, and underscores"
    });
  }

  // Validate name fields (not empty and reasonable length)
  if (firstname.trim().length < 1 || firstname.trim().length > 50) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "First name must be between 1 and 50 characters"
    });
  }

  if (lastname.trim().length < 1 || lastname.trim().length > 50) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "Last name must be between 1 and 50 characters"
    });
  }

  next();
};

const validateLogin = (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "Email and password are required"
    });
  }

  if (!emailRegex.test(email)) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "Invalid email format"
    });
  }

  next();
};

const validatePasswordReset = (req, res, next) => {
  const { email, otp, password } = req.body;

  if (!email || !otp || !password) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "Email, OTP, and new password are required"
    });
  }

  if (!emailRegex.test(email)) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "Invalid email format"
    });
  }

  // Validate OTP format (6 digits)
  const otpRegex = /^\d{6}$/;
  if (!otpRegex.test(otp)) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "OTP must be a 6-digit number"
    });
  }

  if (!passwordRegex.test(password)) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "Password must be at least 6 characters long"
    });
  }

  next();
};

const validateForgotPassword = (req, res, next) => {
  const { email } = req.body;

  if (!email) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "Email is required"
    });
  }

  if (!emailRegex.test(email)) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "Invalid email format"
    });
  }

  next();
};

module.exports = {
  validateRegistration,
  validateLogin,
  validatePasswordReset,
  validateForgotPassword
}; 