import Admin from "../models/Admin.js";
import Otp from "../models/Otp.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { sendOTP } from "../utils/mailer.js";

//Admin Login
export const adminLogin = async (req, res) => {
  const { email, password } = req.body;

  try {
    const admin = await Admin.findOne({ email }).select("+password");

    if (!admin)
      return res
        .status(404)
        .json({ success: false, message: "Admin not found" });

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch)
      return res
        .status(401)
        .json({ success: false, message: "Invalid password" });

    if (admin.isTwoFactorEnabled) {
      const otp = Math.floor(100000 + Math.random() * 900000).toString();

      const otpRecord = await Otp.create({
        userId: admin._id,
        email: admin.email,
        otp,
        expiresAt: Date.now() + 3 * 60 * 1000,
        isUsed: false,
      });

      await sendOTP(admin.email, otp);

      const token = jwt.sign(
        { otpId: otpRecord._id, userId: admin._id },
        process.env.SECRET_KEY,
        { expiresIn: "10m" }
      );

      return res.status(200).json({
        success: true,
        message: "OTP sent to email",
        token,
        isTwoFactorEnabled: true,
      });
    } else {
      const token = jwt.sign(
        { userId: admin._id, email: admin.email },
        process.env.SECRET_KEY,
        {
          expiresIn: "1d",
        }
      );

      res.status(200).json({
        success: true,
        message: "Login successful",
        token,
        admin: {
          _id: admin._id,
          email: admin.email,
          username: admin.username,
          name: admin.name,
        },
      });
    }
  } catch (error) {
    res
      .status(500)
      .json({ success: false, message: "Login failed", error: error.message });
  }
};

// OTP Verify
export const verifyAdminOtp = async (req, res) => {
  const { token, otp } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    const { userId, otpId } = decoded;

    const record = await Otp.findOne({
      _id: otpId,
      userId,
      otp,
      isUsed: false,
      expiresAt: { $gt: Date.now() },
    });

    if (!record) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid or expired OTP" });
    }

    await Otp.findByIdAndUpdate(record._id, { isUsed: true });

    const admin = await Admin.findById(decoded.userId);

    if (!admin) {
      return res
        .status(404)
        .json({ success: false, message: "Admin not found" });
    }

    const finalToken = jwt.sign(
      { userId: admin._id, email: admin.email },
      process.env.SECRET_KEY,
      { expiresIn: "1d" }
    );

    return res.status(200).json({
      success: true,
      message: "OTP verified successfully",
      token: finalToken,
      admin: {
        _id: admin._id,
        email: admin.email,
        username: admin.username,
        name: admin.name,
      },
    });
  } catch (error) {
    return res
      .status(500)
      .json({
        success: false,
        message: "OTP verification failed",
        error: error.message,
      });
  }
};

// GET Admin Profile
export const getAdminProfile = async (req, res) => {
  try {
    const admin = req.admin;

    res.status(200).json({
      success: true,
      message: "Admin profile fetched successfully",
      admin: {
        _id: admin._id,
        name: admin.name,
        email: admin.email,
        username: admin.username,
        isTwoFactorEnabled: admin.isTwoFactorEnabled,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to fetch admin profile",
      error: error.message,
    });
  }
};

//2FA 
export const toggleTwoFactorAdmin = async (req, res) => {
  try {
    const { enable2FA } = req.body;

    if (typeof enable2FA !== "boolean") {
      return res.status(400).json({
        success: false,
        message: "enable2FA must be true or false",
      });
    }

    const admin = await Admin.findById(req.admin._id);

    if (!admin) {
      return res.status(404).json({
        success: false,
        message: "Admin not found",
      });
    }

    admin.isTwoFactorEnabled = enable2FA;
    await admin.save();

    res.status(200).json({
      success: true,
      message: `2FA has been ${enable2FA ? "enabled" : "disabled"} successfully`,
      isTwoFactorEnabled: admin.isTwoFactorEnabled,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to toggle 2FA",
      error: error.message,
    });
  }
};
