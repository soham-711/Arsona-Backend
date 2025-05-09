import express from 'express'
import { forget_password, Otp_Verification, resendPassword, Reset_password } from '../controllers/VerificationController';

const route=express.Router();
route.post("/verification",Otp_Verification)//step-2
route.post("/new_password",Reset_password);//step-3
// 
route.post("/forget-password",forget_password)//step-1
route.post("/password",resendPassword)
export default route