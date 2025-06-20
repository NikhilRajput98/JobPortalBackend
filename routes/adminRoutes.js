import express from "express";
import { adminLogin, getAdminProfile, getAllCompaniesWithPagination,toggleTwoFactorAdmin, verifyAdminOtp } from "../controllers/adminController.js";
import { verifyAdmin } from "../middlewares/adminMiddleware.js";

const router = express.Router();

router.post("/login", adminLogin);
router.post("/verify-otp", verifyAdminOtp);
router.get("/profile", verifyAdmin, getAdminProfile);
router.put("/toggle-2fa-by-id", verifyAdmin, toggleTwoFactorAdmin);
router.get("/companies", verifyAdmin, getAllCompaniesWithPagination)

export default router;
