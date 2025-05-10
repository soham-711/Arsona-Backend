import { Request, Response } from "express";
import userModel from "../models/userModel";
import { sendOtpEmail } from "../utils/sendEmail";
import jwt from "jsonwebtoken";

const otpStore: Record<string, { code: string; expires: number }> = {};

export const Otp_Verification = async (
  req: Request,
  res: Response
): Promise<any> => {
  console.log(req.body);
  const { fullOtp, email } = req.body.Data;
  console.log(email, fullOtp);
  if (!email || !fullOtp) {
    return res
      .status(400)
      .json({ message: "OTP are required", data: null, success: false });
  }

  const record = otpStore[email];

  if (!record) {
    return res
      .status(400)
      .json({ message: "No OTP request found for this email", data: null });
  }

  if (record.code !== fullOtp) {
    return res
      .status(400)
      .json({ message: "Invalid OTP", data: null, success: false });
  }

  if (record.expires < Date.now()) {
    delete otpStore[email];
    return res
      .status(400)
      .json({ message: "OTP has expired", data: null, success: false });
  }

  return res
    .status(200)
    .json({ message: "OTP verification successful", data: null });
};

export const Reset_password = async (
  req: Request,
  res: Response
): Promise<any> => {
      const { newPassword, confirmPassword, email } = req.body as {
      newPassword?: string;
      confirmPassword?: string;
      email?:string
    };

  try {

    if (!newPassword || !confirmPassword) {
      return res.status(400).json({
        message: "All fields are required",
        data: null,
        success: false,
      });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        message: "Passwords do not match",
        data: null,
        success: false,
      });
    }
    const userData = await userModel.findOne({email});

    if (!userData) {
      return res
        .status(404)
        .json({ message: "User not found", data: null, success: false });
    }

    // Optional: Hash new password (recommended)

    userData.password = newPassword;
    await userData.save();
    console.log(userData);

    return res
      .status(200)
      .json({
        message: "Password reset successfully",
        data: null,
        success: true,
      });
  } catch (error) {
    console.error("Reset Password Error:", error);
    return res
      .status(500)
      .json({ message: "Internal Server Error", data: null, success: false });
  }
};

export const forget_password = async (
  req: Request,
  res: Response
): Promise<any> => {
  const { email } = req.body as { email?: string };

  if (!email) {
    return res
      .status(400)
      .json({ message: "Email is required", data: null, success: false });
  }

  const user = await userModel.findOne({ email });
  if (!user) {
    return res
      .status(404)
      .json({ message: "Email is not registered", data: null, success: false });
  }

  const otp = Math.floor(1000 + Math.random() * 9000).toString();
  otpStore[email] = {
    code: otp,
    expires: Date.now() + 2 * 60 * 1000, // 2 minutes
  };

  try {
    await sendOtpEmail(email, otp);
    return res
      .status(200)
      .json({ message: "OTP sent to your email", data: null, success: true });
  } catch (err) {
    console.error("Failed to send OTP:", err);
    return res.status(500).json({
      message: "Could not send OTP. Try again later.",
      data: null,
      success: false,
    });
  }
};

export const resendPassword = async (
  req: Request,
  res: Response
): Promise<any> => {
  try {

    const {email} = req.body;
 console.log(email)
    // Generate new OTP
    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    otpStore[email] = {
      code: otp,
      expires: Date.now() + 2 * 60 * 1000, // valid for 2 minutes
    };

    // Send OTP to email
    await sendOtpEmail(email, otp);

    return res.status(200).json({
      message: "OTP sent to your email",
      success: true,
      data: null,
    });
  } catch (error: any) {
    console.error("Error in resendPassword:", error.message || error);
 console.log(error)
    return res.status(500).json({
      message: "Internal Server Error",
      success: false,
    });
  }
};
