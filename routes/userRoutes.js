import express from "express";
import { sendOtp, verifyOtp, login, getProfile, updateProfile } from "../controllers/userController.js";
import { authenticateUser } from "../middlewares/authMiddleware.js";

const router = express.Router();

router.post("/register", sendOtp);
router.post("/verify-otp", verifyOtp);
router.post("/login", login);
router.get("/profile", authenticateUser, getProfile);
router.put("/profile", authenticateUser, updateProfile);

export default router;
