import nodemailer from "nodemailer";
import dotenv from "dotenv";
dotenv.config();

interface MailOptions {
  from: string;
  to: string;
  subject: string;
  html: string;
}

export async function sendOtpEmail(email: string, otp: string): Promise<void> {
  // Configure your transport (Gmail example)
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: `sohambiswas716@gmail.com`,
      pass: `mzlxeicefciioysu`, // App Password
    },
  });

  const mailOptions: MailOptions = {
    from: `"ARSONA SENTINEL Fire Safety Team" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Secure Your Account – ARSONA SENTINEL OTP Verification",
    html: `
    <div style="font-family: Arial, sans-serif; line-height: 1.6;">
      <h2 style="color:rgb(105, 255, 11);">ARSONA SENTINEL : Smart Monitoring. Safer Living.</h2>
      <p>Dear User,</p>
      <p>For your security and to ensure uninterrupted access to our fire safety services, please use the following One-Time Password (OTP) to verify your account:</p>
      <h3 style="color: #1d3557;">Your OTP Code: <strong>${otp}</strong></h3>
      <p>This code will expire in <strong>2 minutes</strong>. Please do not share it with anyone.</p>
      <p>Our mission is to keep you safe — thank you for trusting ARSONA SENTINEL.</p>
      <hr>
      <small style="color: #555;">If you did not request this, please ignore this message or contact our support team immediately.</small>
    </div>
  `,
  };

  await transporter.sendMail(mailOptions);
}
