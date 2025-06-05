import User from "../models/User.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: "User does not exist" });
    }

    if (!user.isVerified) {
      return res.status(400).json({ message: "Please verify your email first" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Incorrect password" });
    }

    const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY, {
      expiresIn: "1d",
    });

    res.status(200).json({ message: "Login successful", token });

  } catch (error) {
    res.status(500).json({ message: "Login failed", error: error.message });
  }
};
