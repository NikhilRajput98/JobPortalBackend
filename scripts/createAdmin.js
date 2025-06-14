import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import Admin from "../models/Admin.js";

dotenv.config();

const createAdmin = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Connected to DB");

    const hashedPassword = await bcrypt.hash("admin123", 10);

    const admin = new Admin({
      name: "Saumya Shukla",
      username: "saumya",
      email: "saumyashukla56013@gmail.com",
      password: hashedPassword,
      isTwoFactorEnabled: true,  
    });

    await admin.save();
    console.log("Admin created successfully!");
    process.exit();
  } catch (error) {
    console.error("Error creating admin:", error.message);
    process.exit(1);
  }
};

createAdmin();
