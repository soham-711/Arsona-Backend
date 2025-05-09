// server.ts
import express, { Request, Response } from "express";
import cors from "cors";
import dotenv from "dotenv";
import connectDB from "./config/db";
import authRoutes from "./routes/authRoutes";
// import userModel from "./models/userModel";
// import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
// import { sendOtpEmail } from "./utils/sendEmail";
import validationRoutes from "./routes/ValidationCheckRoute"
import verifyRoutes from "./routes/verificationRoute"
import { log } from "console";
import { resendPassword } from "./controllers/VerificationController";
dotenv.config();
connectDB();

const app = express();

// CORS setup
app.use(cors({
  origin: '*',       // or specific mobile origin if known
  credentials: true, // allow cookies
}));
// ! when you sending request from frontend send withCredentials True with data
app.use(express.json());
app.use(cookieParser());
//! home directory
app.get('/', async (req: Request , res: Response): Promise<any> => {
  return res.status(200).send({ message: "Welcome to Backend" });
  
});
// register-login
app.use("/arsona/auth", authRoutes);
// forget password,otp-verification,
app.use("/arsona/otp-verification",verifyRoutes)
//validation routes
app.use("/validate",validationRoutes)
//resend password

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
