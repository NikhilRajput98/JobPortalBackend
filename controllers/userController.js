import User from "../models/User.js";
import Otp from "../models/Otp.js";
import bcrypt from "bcrypt";
import { sendOTP } from "../utils/mailer.js";
import jwt from "jsonwebtoken";
import fs from "fs";
import path from "path";
import dotenv from "dotenv";
dotenv.config();

//Register User
export const registerUser = async (req, res) => {
  const { name, email, password, phoneNo, country, state, city, address } =
    req.body;

  const requiredFields = {
    name,
    email,
    password,
    phoneNo,
    country,
    state,
    city,
  };
  for (let [key, value] of Object.entries(requiredFields)) {
    if (!value || value === "undefined" || value === "") {
      return res
        .status(400)
        .json({ success: false, message: `${key} is required` });
    }
  }

  if (!/^\d{10}$/.test(phoneNo)) {
    return res.status(400).json({
      success: false,
      message:
        "Phone number must be exactly 10 digits and contain only numbers",
    });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res
      .status(400)
      .json({ success: false, message: "Invalid email format" });
  }

  try {
    const existingUser = await User.findOne({ email });

    if (existingUser && existingUser.isVerified) {
      return res
        .status(400)
        .json({ success: false, message: "User already exists and verified" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.findOneAndUpdate(
      { email },
      {
        name,
        email,
        password: hashedPassword,
        phoneNo,
        country,
        state,
        city,
        address,
        isVerified: false,
      },
      { upsert: true, new: true }
    );

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    const otpLog =  await Otp.create({
      userId: user._id,
      email,
      otp,
      expiresAt: new Date(Date.now() + 2 * 60 * 1000), 
    });

    const token = jwt.sign({ id: user._id, otpId:otpLog._id }, process.env.SECRET_KEY, {
      expiresIn: "10m",
    });

    await sendOTP(email, otp);

    res
      .status(200)
      .json({ success: true, message: "OTP sent to your email", token });
  } catch (error) {
    console.log(error);
    res
      .status(500)
      .json({
        success: false,
        message: "Error during registration",
        error: error.message,
      });
  }
};

//Verify user
export const verifyOtp = async (req, res) => {
  const { token, otp } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    const userId = decoded.id;
    const otpId = decoded.otpId;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const record = await Otp.findById(otpId);

    if (!record) {
      return res.status(400).json({
        success: false,
        message: "OTP not found. Please try again.",
      });
    }

    if (record.isUsed) {
      return res.status(400).json({
        success: false,
        message: "OTP already used. Please request a new one.",
      });
    }

    if (record.expiresAt < new Date()) {
      return res.status(400).json({
        success: false,
        message: "OTP expired. Please request again.",
      });
    }

    if (record.otp !== otp) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    await Otp.findByIdAndUpdate(record._id, { isUsed: true });

    await User.findByIdAndUpdate(userId, { isVerified: true });

    return res.status(200).json({ 
      success: true,
      message: "Email verified successfully. You can now log in.",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "OTP verification failed",
      error: error.message,
    });
  }
};


//Login user
export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email }).select("+password"); 

    if (!user || !user.isVerified) {
      return res
        .status(400)
        .json({ success: false, message: "User not verified or doesn't exist" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ success:false, message: "Wrong credentials" });

    const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY, {
      expiresIn: "1d",
    });

    res.status(200).json({ success: true, message: "Login successful", token });
  } catch (error) {
    res.status(500).json({ success:false, message: "Login failed", error: error.message });
  }
};


//Profile fetch
export const getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select("-password");

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    res.status(200).json({
      data: user,
      success: true,
      message: "User profile details fetched successfully !!!",
    });
  } catch (err) {
    res
      .status(500)
      .json({ success: false, message: "Something went wrong", error: err.message });
  }
};

//Update profile
export const updateProfile = async (req, res) => {
  try {
    const userId = req.user.id;
    const { name, phoneNo, country, state, city } = req.body;

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    user.name = name || user.name;
    user.phoneNo = phoneNo || user.phoneNo;
    user.country = country || user.country;
    user.state = state || user.state;
    user.city = city || user.city;

    if (phoneNo && !/^\d{10}$/.test(phoneNo)) {
      return res.status(400).json({
        success: false,
        message:
          "Phone number must be exactly 10 digits and contain only numbers",
      });
    }

    if (req.file) {
      if (user.profileImage) {
        const oldImagePath = path.join(
          "uploads/profileImages",
          user.profileImage
        );
        if (fs.existsSync(oldImagePath)) {
          fs.unlinkSync(oldImagePath);
          console.log("Old image deleted:", oldImagePath);
        }
      }

      user.profileImage = req.file.filename;
    } else {
      console.log("No new image uploaded. Keeping previous image.");
    }

    await user.save();
    const userProfile = await User.findById(userId).select("-password")
    res
      .status(200)
      .json({ success: true, message: "Profile updated successfully", data: userProfile });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error updating profile", error });
  }
};
