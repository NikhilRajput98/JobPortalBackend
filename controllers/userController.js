import User from "../models/User.js";
import Otp from "../models/Otp.js";
import bcrypt from "bcrypt";
import { sendOTP } from "../utils/mailer.js";
import jwt from "jsonwebtoken";
import fs from "fs";
import path from "path";
import dotenv from "dotenv";
dotenv.config();

export const sendOtp = async (req, res) => {
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
      return res.status(400).json({ message: `${key} is required` });
    }
  }

  if (!/^\d{10}$/.test(phoneNo)) {
    return res.status(400).json({
      message:
        "Phone number must be exactly 10 digits and contain only numbers",
    });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({
      message: "Invalid email format",
    });
  }

  try {
    const existingUser = await User.findOne({ email });

    if (existingUser && existingUser.isVerified) {
      return res
        .status(400)
        .json({ message: "User already exists and verified" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedPassword = await bcrypt.hash(password, 10);

    await Otp.findOneAndUpdate(
      { email },
      { otp, expiresAt: new Date(Date.now() + 10 * 60 * 1000) },
      { upsert: true, new: true }
    );

    await User.findOneAndUpdate(
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

    await sendOTP(email, otp);

    res.status(200).json({ message: "OTP sent to your email" });
  } catch (error) {
    console.log(error);
    res
      .status(500)
      .json({ message: "Error sending OTP", error: error.message });
  }
};

export const verifyOtp = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const record = await Otp.findOne({ email });

    if (!record) {
      return res
        .status(400)
        .json({ message: "OTP not found. Please try again." });
    }

    if (record.otp !== otp) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    if (record.expiresAt < new Date()) {
      return res
        .status(400)
        .json({ message: "OTP expired. Please request again." });
    }

    await User.findOneAndUpdate({ email }, { isVerified: true });
    await Otp.deleteOne({ email });

    res
      .status(200)
      .json({ message: "Email verified successfully. You can now log in." });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error verifying OTP", error: error.message });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user || !user.isVerified) {
      return res
        .status(400)
        .json({ message: "User not verified or doesn't exist" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Wrong credentials" });

    const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY, {
      expiresIn: "1d",
    });

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    res.status(500).json({ message: "Login failed", error: error.message });
  }
};

export const getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      data: user,
      message: "User profile details fetched successfully !!!",
    });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Something went wrong", error: err.message });
  }
};

export const updateProfile = async (req, res) => {
  try {
    const userId = req.user.id;
    const { name, phoneNo, country, state, city } = req.body;

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    user.name = name || user.name;
    user.phoneNo = phoneNo || user.phoneNo;
    user.country = country || user.country;
    user.state = state || user.state;
    user.city = city || user.city;

    if (phoneNo && !/^\d{10}$/.test(phoneNo)) {
      return res.status(400).json({
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
    res
      .status(200)
      .json({ message: "Profile updated successfully", data: user });
  } catch (error) {
    res.status(500).json({ message: "Error updating profile", error });
  }
};
