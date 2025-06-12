import mongoose from "mongoose";

const adminSchema = new mongoose.Schema(
  {
    name: { 
        type: String, 
        required: true 
    },
    username: {
      type: String,
      required: true,
      unique: true,
      match: [/^[a-zA-Z0-9_]+$/, "Username must contain only letters, numbers, and underscores"],
    },
    email: {
      type: String,
      required: true,
      unique: true,
      match: [/^\S+@\S+\.\S+$/, "Please enter a valid email"],
    },
    password: { 
        type: String, 
        required: true 
    },
    isTwoFactorEnabled: { 
        type: Boolean, 
        default: false 
    },
    // isVerified: { 
    //     type: Boolean, 
    //     default: true 
    // },
    profileImage: { 
        type: String,  
    },
  },
  { timestamps: true }
);

export default mongoose.model("Admin", adminSchema);
