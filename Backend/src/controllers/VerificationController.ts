import { Request, Response } from "express";
import userModel from "../models/userModel";
import { sendOtpEmail } from "../utils/sendEmail";
import jwt from "jsonwebtoken";

const otpStore: Record<string, { code: string; expires: number }> = {};

export const Otp_Verification = async (
  req: Request,
  res: Response
): Promise<any> => {
  const { otp } = req.body as { otp?: string };
  const token = req.cookies.access_token;
  console.log(token);
  if (!token) {
    return res
      .status(401)
      .send({ message: "Internal Server Error", user: null, success: false });
  }
  const decoded = jwt.verify(
    token,
    process.env.JWT_SECRET || "secret"
  ) as jwt.JwtPayload;
  const userData = await userModel.findById(decoded.id);
  const email = userData?.email;
  console.log(email);

  if (!email || !otp) {
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

  if (record.code !== otp) {
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
  const token = req.cookies.access_token;
  console.log(token);

  if (!token) {
    return res
      .status(401)
      .send({ message: "Internal Server Error", user: null, success: false });
  }
  try {
    const { newPassword, confirmPassword } = req.body as {
      newPassword?: string;
      confirmPassword?: string;
    };

    if (!newPassword || !confirmPassword) {
      return res
        .status(400)
        .json({
          message: "All fields are required",
          data: null,
          success: false,
        });
    }

    if (newPassword !== confirmPassword) {
      return res
        .status(400)
        .json({
          message: "Passwords do not match",
          data: null,
          success: false,
        });
    }
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "secret"
    ) as jwt.JwtPayload;
    const userData = await userModel.findById(decoded.id);
    const email = userData?.email;

    const user = await userModel.findOne({ email });
    if (!user) {
      return res
        .status(404)
        .json({ message: "User not found", data: null, success: false });
    }

    // Optional: Hash new password (recommended)

    user.password = newPassword;
    await user.save();
    console.log(user);
    
    return res
      .status(200)
      .json({ message: "Password reset successfully", data: null,success: true });
  } catch (error) {
    console.error("Reset Password Error:", error);
    return res
      .status(500)
      .json({ message: "Internal Server Error", data: null,success: false });
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
    return res
      .status(500)
      .json({
        message: "Could not send OTP. Try again later.",
        data: null,
        success: false,
      });
  }
};


export const resendPassword = async (req: Request, res: Response): Promise<any> => {
  try {
    const token = req.cookies.access_token;

    if (!token) {
      return res.status(401).json({
        message: 'Unauthorized: Token missing',
        success: false,
        user: null,
      });
    }

    // Verify token and extract user ID
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret') as jwt.JwtPayload;
    console.log(decoded);
    

    if (!decoded?.id) {
      return res.status(401).json({
        message: 'Invalid token payload',
        success: false,
        user: null,
      });
    }

    // Fetch user from database
    const userData = await userModel.findById(decoded.id); console.log(userData);
    
    if (!userData || !userData.email) {
      return res.status(404).json({
        message: 'User not found',
        success: false,
      });
    }

    const email = userData.email;

    // Generate new OTP
    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    otpStore[email] = {
      code: otp,
      expires: Date.now() + 2 * 60 * 1000, // valid for 2 minutes
    };

    // Send OTP to email
    await sendOtpEmail(email, otp);

    return res.status(200).json({
      message: 'OTP sent to your email',
      success: true,
      data: null,
    });

  } catch (error: any) {
    console.error('Error in resendPassword:', error.message || error);

    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        message: 'Invalid token',
        success: false,
      });
    }

    return res.status(500).json({
      message: 'Internal Server Error',
      success: false,
    });
  }
};