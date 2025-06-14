import express from "express";
import { adminLogin, getAdminProfile,toggleTwoFactorAdmin, verifyAdminOtp } from "../controllers/adminController.js";
import { verifyAdmin } from "../middlewares/adminMiddleware.js";

const router = express.Router();

router.post("/login", adminLogin);
router.post("/verify-otp", verifyAdminOtp);
router.get("/profile", verifyAdmin, getAdminProfile);
router.patch("/toggle-2fa-by-id", toggleTwoFactorAdmin)

export default router;
