import nodemailer from "nodemailer";
import dotenv from "dotenv";
dotenv.config();



export const sendOTP = async (email, otp) => {
  
  const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS, 
  }
});
  const mailOptions = {
    from: process.env.SMTP_USER,
    to: email,
    subject: "Verify your Email - OTP",
    html: `
      <h2>Your OTP Code</h2>
      <p>Please use the following OTP to verify your email address:</p>
      <h3>${otp}</h3>
      <p>This OTP is valid for 10 minutes.</p>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log("OTP sent to:", email);
  } catch (error) {
    console.error("Failed to send OTP email:", error);
    throw new Error("Could not send OTP email");
  }
};
