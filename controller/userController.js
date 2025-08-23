const db = require("../db/dbConfig");
const bcrypt = require("bcrypt");
const { StatusCodes } = require("http-status-codes");
const jwt = require("jsonwebtoken");
require("dotenv").config();

// Utility functions
const userUtility = {
  generateDigitOTP: () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
  },
  
  sendSMS: async (employeeId, otp) => {
    // Placeholder for SMS sending functionality
    // In a real application, you would use a service like Twilio, etc.
    console.log(`OTP ${otp} sent to employee ${employeeId}`);
    return true;
  }
};

async function register(req, res) {
  const { username, firstname, lastname, employee_id, password } = req.body;

  if (!username || !firstname || !lastname || !employee_id || !password) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "Please provide all information" });
  }

  // Validate employee_id is 4 digits
  if (!/^\d{4}$/.test(employee_id)) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "Employee ID must be a 4-digit number" });
  }

  try {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    const existingUser = await db.client.query(
      "SELECT username, userid FROM users WHERE username = $1 OR employee_id = $2",
      [username, employee_id]
    );
    
    if (existingUser.rows.length > 0) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ msg: "User already exists" });
    }
    
    // Insert the user data into the database
    await db.client.query(
      "INSERT INTO users (username, firstname, lastname, employee_id, password) VALUES ($1, $2, $3, $4, $5)",
      [username, firstname, lastname, employee_id, hashedPassword]
    );

    return res
      .status(StatusCodes.CREATED)
      .json({ msg: "User created successfully" });
  } catch (error) {
    console.error(error.message);
    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ msg: "Something went wrong, try later" });
  }
}

async function login(req, res) {
  const { employee_id, password } = req.body;
  
  if (!employee_id || !password) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "Please provide all information" });
  }
  
  try {
    const user = await db.client.query(
      "SELECT username, employee_id, userid, password FROM users WHERE employee_id = $1",
      [employee_id]
    );
    
    if (user.rows.length === 0) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ msg: "Invalid credentials" });
    }
    
    const isMatch = await bcrypt.compare(password, user.rows[0].password);
    
    if (!isMatch) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ msg: "Invalid credentials" });
    }
    
    const token = jwt.sign(
      { userId: user.rows[0].userid, username: user.rows[0].username },
      process.env.JWT_SECRET,
      {
        expiresIn: "1d", // Token will expire in 1 day
      }
    );
    
    res.status(StatusCodes.OK).json({
      msg: "Login successful",
      token,
      username: user.rows[0].username,
      employee_id: user.rows[0].employee_id,
      userId: user.rows[0].userid,
    });
  } catch (error) {
    console.error(error.message);
    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ msg: "Something went wrong, try later" });
  }
}

async function checkUser(req, res) {
  const username = req.user.username;
  const userid = req.user.userId;
  return res
    .status(StatusCodes.OK)
    .json({ msg: "Valid user", username, userid });
}

const resetPassword = async (req, res) => {
  const { employee_id, otp, password } = req.body;

  if (!employee_id || !otp || !password) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "Please provide all required information" });
  }

  // Validate OTP format: Ensure it's a 6-digit number
  const otpRegex = /^\d{6}$/;
  if (!otpRegex.test(otp)) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "OTP must be a 6-digit number" });
  }
  
  try {
    const user = await db.client.query(
      "SELECT * FROM users WHERE employee_id = $1 AND otp = $2 AND otp_expires > $3",
      [employee_id, otp, new Date()]
    );

    if (user.rows.length === 0) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ msg: "Invalid or Expired OTP" });
    }
    
    // hash the new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // update the user's password and clear the OTP and its expiration
    await db.client.query(
      "UPDATE users SET password = $1, otp = NULL, otp_expires = NULL WHERE employee_id = $2",
      [hashedPassword, employee_id]
    );

    return res.status(StatusCodes.OK).json({
      msg: "Password reset successfully. You can now log in with your new password",
    });
  } catch (error) {
    console.error(error);
    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ msg: "Server error. Please try again later." });
  }
};

const requestOTP = async (req, res) => {
  const { employee_id } = req.body;

  if (!employee_id) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "Please provide employee ID" });
  }

  try {
    const user = await db.client.query(
      "SELECT * FROM users WHERE employee_id = $1",
      [employee_id]
    );

    if (user.rows.length === 0) {
      return res.status(StatusCodes.NOT_FOUND).json({ msg: "User not found" });
    }

    // generate OTP using userUtility
    const otp = userUtility.generateDigitOTP();

    // for 10 min
    const expireAt = new Date(Date.now() + 10 * 60 * 1000);

    // store the otp and expiration on database
    await db.client.query(
      "UPDATE users SET otp = $1, otp_expires = $2 WHERE employee_id = $3",
      [otp, expireAt, employee_id]
    );

    // send the OTP via SMS using userUtility
    await userUtility.sendSMS(employee_id, otp);
    res.status(StatusCodes.OK).json({ msg: "OTP sent to your registered phone number" });
  } catch (error) {
    console.error(error);
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      msg: "Server error, Please try again later.",
    });
  }
};

module.exports = { register, login, checkUser, resetPassword, requestOTP };