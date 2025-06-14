import Company from "../models/Company.js";
import Otp from "../models/Otp.js";
import Job from "../models/Job.js";
import Application from "../models/Application.js";
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


//Company Dashboard
export const getCompanyDashboard = async (req, res) => {
  try {
    const companyId = req.company._id;

    //Company Details
    const company = await Company.findById(companyId).select("-password");

    //Jobs Posted by Company
    const jobs = await Job.find({ company: companyId }).sort({ createdAt: -1 });

    const jobIds = jobs.map((job) => job._id);

    //All Applications to this Company's Jobs
    const applications = await Application.find({ job: { $in: jobIds } });

    //Dashboard Stats
    const stats = {
      totalJobs: jobs.length,
      activeJobs: jobs.filter((j) => !j.deadline || new Date(j.deadline) > new Date()).length,
      expiredJobs: jobs.filter((j) => j.deadline && new Date(j.deadline) <= new Date()).length,
      totalApplications: applications.length,
      pendingApplications: applications.filter((a) => a.status === "pending").length,
      shortlisted: applications.filter((a) => a.status === "shortlisted").length,
      rejected: applications.filter((a) => a.status === "rejected").length,
    };

    //Recent 5 Jobs
    const recentJobs = jobs.slice(0, 5);

    //Recent 5 Applications with User Info
    const recentApplicants = await Application.find({ job: { $in: jobIds } })
      .sort({ createdAt: -1 })
      .limit(5)
      .populate("user", "name email resume");

    res.status(200).json({
      success: true,
      message: "Dashboard data fetched successfully",
      company,
      stats,
      recentJobs,
      recentApplicants,
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "Failed to fetch dashboard data",
      error: err.message,
    });
  }
};







































// import Company from "../models/Company.js";
// import Otp from "../models/Otp.js";
// import Job from "../models/Job.js";
// import bcrypt from "bcrypt";
// import jwt from "jsonwebtoken";
// import { sendOTP } from "../utils/mailer.js";

// //Register Company
// export const registerCompany = async (req, res) => {
//   const {
//     name,
//     email,
//     password,
//     industryType,
//     location,
//     logo,
//     description,
//     website,
//     companyType,
//   } = req.body;

//   try {
//     const requiredFields = {
//       name,
//       email,
//       password,
//       industryType,
//       location,
//     };

//     for (const [key, value] of Object.entries(requiredFields)) {
//       if (!value || value.trim() === "") {
//         return res
//           .status(400)
//           .json({ success: false, message: `${key} is required` });
//       }
//     }

//     const exist = await Company.findOne({ email });
//     if (exist)
//       return res
//         .status(400)
//         .json({ success: false, message: "Company already registered" });

//     const hashedPassword = await bcrypt.hash(password, 10);

//     const company = await Company.create({
//       name,
//       email,
//       password: hashedPassword,
//       industryType,
//       location,
//       logo: logo || "",
//       description: description || "",
//       website: website || "",
//       companyType: companyType || "",
//     });

//     // Generate OTP and store it with company reference
//     const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
//     const otpRecord = await Otp.create({
//       email,
//       code: otpCode,
//       companyId: company._id,
//       expiresAt: new Date(Date.now() + 3 * 60 * 1000),
//     });

//     await sendOTP(email, otpCode, "Company Email Verification");

//     const token = jwt.sign(
//       { companyId: company._id, otpId: otpRecord._id },
//       process.env.SECRET_KEY,
//       { expiresIn: "15m" }
//     );

//     res.status(201).json({
//       success: true,
//       message: "OTP sent to email for verification",
//       token,
//     });
//   } catch (error) {
//     res.status(500).json({
//       success: false,
//       message: "Registration error",
//       error: error.message,
//     });
//   }
// };

// //Verify OTP
// export const verifyCompanyOtp = async (req, res) => {
//   const { token, otp } = req.body;

//   try {
//     const decoded = jwt.verify(token, process.env.SECRET_KEY);
//     const { companyId, otpId } = decoded;

//     const record = await Otp.findById(otpId);
//     if (
//       !record ||
//       record.code !== otp ||
//       record.isUsed ||
//       record.expiresAt < Date.now()
//     ) {
//       return res
//         .status(400)
//         .json({ success: false, message: "Invalid or expired OTP" });
//     }

//     await Otp.findByIdAndUpdate(otpId, { isUsed: true });
//     await Company.findByIdAndUpdate(companyId, { isVerified: true });

//     res
//       .status(200)
//       .json({ success: true, message: "Email verified successfully" });
//   } catch (err) {
//     res
//       .status(401)
//       .json({ success: false, message: "Invalid or expired token" });
//   }
// };

// //Company Login
// export const loginCompany = async (req, res) => {
//   const { email, password } = req.body;

//   try {
//     const company = await Company.findOne({ email }).select("+password");
//     if (!company || !(await bcrypt.compare(password, company.password))) {
//       return res
//         .status(400)
//         .json({ success: false, message: "Invalid credentials" });
//     }

//     if (!company.isVerified) {
//       return res
//         .status(403)
//         .json({ success: false, message: "Email not verified" });
//     }

//     const token = jwt.sign({ id: company._id }, process.env.SECRET_KEY, {
//       expiresIn: "7d",
//     });

//     res.status(200).json({
//       success: true,
//       message: "Login successful",
//       token,
//       twoFA: company.isTwoFactorEnabled,
//       company: {
//         _id: company._id,
//         name: company.name,
//         email: company.email,
//         industryType: company.industryType,
//         location: company.location,
//       },
//     });
//   } catch (err) {
//     res
//       .status(500)
//       .json({ success: false, message: "Login failed", error: err.message });
//   }
// };

// //Toggle 2FA
// export const toggle2FA = async (req, res) => {
//   try {
//     const company = await Company.findById(req.company._id);
//     company.isTwoFactorEnabled = !company.isTwoFactorEnabled;
//     await company.save();

//     res.status(200).json({
//       success: true,
//       message: "2FA setting updated",
//       twoFA: company.isTwoFactorEnabled,
//     });
//   } catch (err) {
//     res.status(500).json({ success: false, message: "Failed to toggle 2FA" });
//   }
// };

// //Post Job
// export const postJob = async (req, res) => {
//   try {
//     const job = await Job.create({ ...req.body, company: req.company._id });

//     await Company.findByIdAndUpdate(req.company._id, {
//       $push: { jobs: job._id },
//     });

//     res.status(201).json({ success: true, job });
//   } catch (err) {
//     res
//       .status(500)
//       .json({
//         success: false,
//         message: "Failed to post job",
//         error: err.message,
//       });
//   }
// };

// //Get Dashboard
// export const getDashboard = async (req, res) => {
//   try {
//     const company = await Company.findById(req.company._id).populate("jobs");

//     res.status(200).json({ success: true, company });
//   } catch (err) {
//     res
//       .status(500)
//       .json({ success: false, message: "Failed to fetch dashboard" });
//   }
// };

// //Update Company Profile (Optional)
// export const updateCompanyProfile = async (req, res) => {
//   try {
//     const updates = req.body;

//     if (req.file) {
//       updates.logo = req.file.path;
//     }

//     const company = await Company.findByIdAndUpdate(req.company._id, updates, {
//       new: true,
//     });

//     res.status(200).json({ success: true, company });
//   } catch (err) {
//     res
//       .status(500)
//       .json({
//         success: false,
//         message: "Failed to update profile",
//         error: err.message,
//       });
//   }
// };
