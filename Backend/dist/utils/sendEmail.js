"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sendOtpEmail = sendOtpEmail;
const nodemailer_1 = __importDefault(require("nodemailer"));
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
function sendOtpEmail(email, otp) {
    return __awaiter(this, void 0, void 0, function* () {
        // Configure your transport (Gmail example)
        const transporter = nodemailer_1.default.createTransport({
            service: "gmail",
            auth: {
                user: `sohambiswas716@gmail.com`,
                pass: `mzlxeicefciioysu`, // App Password
            },
        });
        const mailOptions = {
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
        yield transporter.sendMail(mailOptions);
    });
}
