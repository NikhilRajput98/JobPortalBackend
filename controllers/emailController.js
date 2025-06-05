import Otp from "../models/Otp.js";
import User from "../models/User.js";
import bcrypt from "bcrypt";
import { sendOTP } from "../utils/mailer.js";

// Step 1: Send OTP
export const sendOtp = async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser && existingUser.isVerified) {
      return res.status(400).json({ message: "User already exists and verified" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedPassword = await bcrypt.hash(password, 10);

    // Upsert OTP document
    await Otp.findOneAndUpdate(
      { email },
      { otp, expiresAt: new Date(Date.now() + 10 * 60 * 1000) }, // 10 mins expiry
      { upsert: true, new: true }
    );

    // Upsert user document (not verified yet)
    await User.findOneAndUpdate(
      { email },
      { name, email, password: hashedPassword, isVerified: false },
      { upsert: true, new: true }
    );

    await sendOTP(email, otp);

    res.status(200).json({ message: "OTP sent to email" });

  } catch (error) {
    console.log(error);
    
    res.status(500).json({ message: "Error sending OTP", error: error.message });
  }
};

// Step 2: Verify OTP & register
export const verifyOtp = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const record = await Otp.findOne({ email });

    if (!record) {
      return res.status(400).json({ message: "OTP not found. Please request again." });
    }

    if (record.otp !== otp) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    if (record.expiresAt < new Date()) {
      return res.status(400).json({ message: "OTP expired. Please request again." });
    }

    // Update user verification status
    await User.findOneAndUpdate({ email }, { isVerified: true });
    // Delete OTP record
    await Otp.deleteOne({ email });

    res.status(200).json({ message: "Email verified successfully. You can now login." });

  } catch (error) {
    res.status(500).json({ message: "Error verifying OTP", error: error.message });
  }
};
