const { StatusCodes } = require("http-status-codes");

// Employee ID validation regex - must be exactly 4 digits
const employeeIdRegex = /^\d{4}$/;

// Password validation - at least 6 characters
const passwordRegex = /^.{6,}$/;

// Username validation - alphanumeric and underscore, 3-20 characters
const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;

const validateRegistration = (req, res, next) => {
  const { username, firstname, lastname, employee_id, password } = req.body;

  // Check if all required fields are present
  if (!username || !firstname || !lastname || !employee_id || !password) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "All fields are required",
      missing: {
        username: !username,
        firstname: !firstname,
        lastname: !lastname,
        employee_id: !employee_id,
        password: !password
      }
    });
  }

  // Validate employee_id format (must be exactly 4 digits)
  if (!employeeIdRegex.test(employee_id)) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "Employee ID must be a 4-digit number"
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
  const { employee_id, password } = req.body;

  if (!employee_id || !password) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "Employee ID and password are required"
    });
  }

  // Validate employee_id format (must be exactly 4 digits)
  if (!employeeIdRegex.test(employee_id)) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "Employee ID must be a 4-digit number"
    });
  }

  next();
};

const validatePasswordReset = (req, res, next) => {
  const { employee_id, otp, password } = req.body;

  if (!employee_id || !otp || !password) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "Employee ID, OTP, and new password are required"
    });
  }

  // Validate employee_id format (must be exactly 4 digits)
  if (!employeeIdRegex.test(employee_id)) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "Employee ID must be a 4-digit number"
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
  const { employee_id } = req.body;

  if (!employee_id) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "Employee ID is required"
    });
  }

  // Validate employee_id format (must be exactly 4 digits)
  if (!employeeIdRegex.test(employee_id)) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      msg: "Employee ID must be a 4-digit number"
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