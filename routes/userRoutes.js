import express from "express";
import upload from "../middlewares/upload.js";
import { verifyOtp, login, getProfile, updateProfile, registerUser } from "../controllers/userController.js";
import { authenticateUser } from "../middlewares/authMiddleware.js";

const router = express.Router();

router.post("/register", registerUser);
router.post("/verify-otp", verifyOtp);
router.post("/login", login);
router.get("/profile", authenticateUser, getProfile);
router.put("/update-profile", authenticateUser, upload.single('profileImage'), updateProfile);

export default router;
