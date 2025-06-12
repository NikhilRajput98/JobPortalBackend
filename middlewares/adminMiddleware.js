import jwt from "jsonwebtoken";
import Admin from "../models/Admin.js";

export const verifyAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ success: false, message: "Unauthorized: No token provided" });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.SECRET_KEY);

    const admin = await Admin.findById(decoded.userId);

    if (!admin) {
      return res.status(404).json({ success: false, message: "Admin not found" });
    }

    req.admin = admin;

    next(); 
  } catch (error) {
    return res.status(401).json({ success: false, message: "Invalid or expired token", error: error.message });
  }
};
