import express from "express";
import { adminLogin, getAdminProfile, verifyAdminOtp } from "../controllers/adminController.js";
import { verifyAdmin } from "../middlewares/adminMiddleware.js";

const router = express.Router();

router.post("/login", adminLogin);
router.post("/verify-otp", verifyAdminOtp);
router.get("/profile", verifyAdmin, getAdminProfile);

export default router;
