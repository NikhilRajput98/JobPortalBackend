import express from "express";
import { registerCompany, verifyCompanyOtp, companyLogin, verifyCompanyLoginOtp, toggleTwoFactor, getCompanyProfile, updateCompanyProfile } from "../controllers/companyController.js";
import { authCompany } from "../middlewares/companyMiddleware.js";

const router = express.Router();

router.post("/register", registerCompany);
router.post("/verify", verifyCompanyOtp);
router.post("/login", companyLogin);
router.post("/verify-login-otp", verifyCompanyLoginOtp);
router.patch("/2fa-toggle", authCompany, toggleTwoFactor);
router.get("/profile", authCompany, getCompanyProfile )
router.put("/update", authCompany, updateCompanyProfile)


export default router;
