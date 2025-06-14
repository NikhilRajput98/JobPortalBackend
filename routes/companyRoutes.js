import express from "express";
import { registerCompany, verifyCompanyOtp, companyLogin, verifyCompanyLoginOtp, toggleTwoFactor, getCompanyDashboard } from "../controllers/companyController.js";
import { authCompany } from "../middlewares/companyMiddleware.js";

const router = express.Router();

router.post("/register", registerCompany);
router.post("/verify", verifyCompanyOtp);
router.post("/login", companyLogin);
router.post("/verify-login-otp", verifyCompanyLoginOtp);
router.patch("/2fa-toggle", authCompany, toggleTwoFactor);
router.get("/dashboard", authCompany, getCompanyDashboard);

export default router;
