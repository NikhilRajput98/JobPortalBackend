import jwt from "jsonwebtoken";
import Company from "../models/Company.js";

export const authCompany = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized. Token missing.",
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY);

    const company = await Company.findById(decoded.id);

    if (!company) {
      return res.status(404).json({
        success: false,
        message: "Company not found",
      });
    }

    req.company = company;
    next(); 
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token",
      error: error.message,
    });
  }
};
