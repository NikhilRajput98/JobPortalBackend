import Company from "../models/Company.js";
import Otp from "../models/Otp.js";
// import Job from "../models/Job.js";
// import Application from "../models/Application.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { sendOTP } from "../utils/mailer.js";

//Register Company
export const registerCompany = async (req, res) => {
  const {
    name,
    email,
    password,
    industryType,
    location,
    logo,
    description,
    website,
    companyType,
  } = req.body;

  const requiredFields = {
    name,
    email,
    password,
    industryType,
    location,
  };

  for (let [key, value] of Object.entries(requiredFields)) {
    if (!value || value === "undefined" || value === "") {
      return res
        .status(400)
        .json({ success: false, message: `${key} is required` });
    }
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res
      .status(400)
      .json({ success: false, message: "Invalid email format" });
  }

  try {
    const existingCompany = await Company.findOne({ email });

    if (existingCompany && existingCompany.isVerified) {
      return res
        .status(400)
        .json({ success: false, message: "Company already registered and verified" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const company = await Company.findOneAndUpdate(
      { email },
      {
        name,
        email,
        password: hashedPassword,
        industryType,
        location,
        logo,
        description,
        website,
        companyType,
        isVerified: false,
      },
      { upsert: true, new: true }
    );

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    const otpLog = await Otp.create({
      email,
      otp,
      userId: company._id,
      expiresAt: new Date(Date.now() + 2 * 60 * 1000),
    });

    const token = jwt.sign(
      { id: company._id, otpId: otpLog._id },
      process.env.SECRET_KEY,
      { expiresIn: "10m" }
    );

    await sendOTP(email, otp);

    res.status(200).json({
      success: true,
      message: "OTP sent to company email",
      token,
    });
  } catch (error) {
    console.log("Company Register Error:", error);
    res.status(500).json({
      success: false,
      message: "Error during company registration",
      error: error.message,
    });
  }
};


//verify company 
export const verifyCompanyOtp = async (req, res) => {
  const { token, otp } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    const companyId = decoded.id;
    const otpId = decoded.otpId;

    const company = await Company.findById(companyId);
    if (!company) {
      return res.status(404).json({
        success: false,
        message: "Company not found",
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
    await Company.findByIdAndUpdate(companyId, { isVerified: true });

    return res.status(200).json({
      success: true,
      message: "Company verified successfully. You can now log in.",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "OTP verification failed",
      error: error.message,
    });
  }
};

//Login Company with 2FA
export const companyLogin = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ success: false, message: "Email and password are required" });

  try {
    const company = await Company.findOne({ email }).select("+password");
    if (!company)
      return res.status(404).json({ success: false, message: "Company not found" });

    if (!company.isVerified)
      return res.status(401).json({ success: false, message: "Please verify your email first" });

    const isMatch = await bcrypt.compare(password, company.password);
    if (!isMatch)
      return res.status(401).json({ success: false, message: "Invalid credentials" });

    //Check if 2FA is enabled
    if (company.isTwoFactorEnabled) {
      const otp = Math.floor(100000 + Math.random() * 900000).toString();

      const otpLog = await Otp.create({
        userId: company._id,
        email,
        otp,
        expiresAt: new Date(Date.now() + 3 * 60 * 1000),
      });

      const token = jwt.sign({ id: company._id, otpId: otpLog._id }, process.env.SECRET_KEY, {
        expiresIn: "10m",
      });

      await sendOTP(email, otp);

      return res.status(200).json({
        success: true,
        message: "2FA is enabled. OTP sent to email.",
        token,
      });
    }

    //2FA not enabled, login directly
    const token = jwt.sign({ id: company._id }, process.env.SECRET_KEY, {
      expiresIn: "7d",
    });

    return res.status(200).json({
      success: true,
      message: "Login successful",
      token,
      company: {
        _id: company._id,
        name: company.name,
        email: company.email,
        industryType: company.industryType,
        location: company.location,
        isTwoFactorEnabled: company.isTwoFactorEnabled,
      },
    });
  } catch (error) {
    console.error("Company login error:", error);
    return res.status(500).json({
      success: false,
      message: "Something went wrong during login",
      error: error.message,
    });
  }
};

//OTP Verify after login (2FA)
export const verifyCompanyLoginOtp = async (req, res) => {
  const { token, otp } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    const companyId = decoded.id;
    const otpId = decoded.otpId;

    const company = await Company.findById(companyId);
    if (!company)
      return res.status(404).json({ success: false, message: "Company not found" });

    const record = await Otp.findById(otpId);
    if (!record)
      return res.status(400).json({ success: false, message: "OTP not found" });

    if (record.isUsed)
      return res.status(400).json({ success: false, message: "OTP already used" });

    if (record.expiresAt < new Date())
      return res.status(400).json({ success: false, message: "OTP expired" });

    if (record.otp !== otp)
      return res.status(400).json({ success: false, message: "Invalid OTP" });

    await Otp.findByIdAndUpdate(otpId, { isUsed: true });

    //Now provide full login token
    const finalToken = jwt.sign({ id: company._id }, process.env.SECRET_KEY, {
      expiresIn: "7d",
    });

    return res.status(200).json({
      success: true,
      message: "2FA OTP verified. Login successful.",
      token: finalToken,
      company: {
        _id: company._id,
        name: company.name,
        email: company.email,
        industryType: company.industryType,
        location: company.location,
        isTwoFactorEnabled: company.isTwoFactorEnabled,
      },
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "OTP verification failed",
      error: error.message,
    });
  }
};

// Toggle 2FA
export const toggleTwoFactor = async (req, res) => {
  try {
    const { enable2FA } = req.body;

    if (typeof enable2FA !== "boolean") {
      return res.status(400).json({
        success: false,
        message: "enable2FA must be true or false",
      });
    }

    const company = await Company.findById(req.company._id);

    if (!company) {
      return res.status(404).json({
        success: false,
        message: "Company not found",
      });
    }

    company.isTwoFactorEnabled = enable2FA;
    await company.save();

    res.status(200).json({
      success: true,
      message: `2FA has been ${enable2FA ? "enabled" : "disabled"} successfully`,
      isTwoFactorEnabled: company.isTwoFactorEnabled,
    });
  } catch (error) {
    console.error("Toggle 2FA Error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to toggle 2FA",
      error: error.message,
    });
  }
};

// GET Company Profile
export const getCompanyProfile = async (req, res) => {
  try {
    const company = await Company.findById(req.company._id).select("-password -__v");

    if (!company) {
      return res.status(404).json({
        success: false,
        message: "Company not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Company profile fetched successfully",
      company: {
        _id: company._id,
        name: company.name,
        industryType: company.industryType,
        companyType: company.companyType,
        location: company.location,
        description: company.description,
        website: company.website,
        logo: company.logo,
        isVerified: company.isVerified,
        isTwoFactorEnabled: company.isTwoFactorEnabled,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to fetch company profile",
      error: error.message,
    });
  }
};


// UPDATE Company Profile
export const updateCompanyProfile = async (req, res) => {
  try {
    const company = await Company.findById(req.company._id);

    if (!company) {
      return res.status(404).json({ success: false, message: "Company not found" });
    }

    const updatableFields = [
      "name",
      "industryType",
      "companyType",
      "location",
      "description",
      "website",
      "logo"
    ];

    updatableFields.forEach((field) => {
      if (req.body[field] !== undefined) {
        company[field] = req.body[field];
      }
    });

    await company.save();

    const updatedCompany = await Company.findById(company._id).select("-password -__v");

    res.status(200).json({
      success: true,
      message: "Company profile updated successfully",
      company: updatedCompany,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to update company profile",
      error: error.message,
    });
  }
};

