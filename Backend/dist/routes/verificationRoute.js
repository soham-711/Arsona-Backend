"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const VerificationController_1 = require("../controllers/VerificationController");
const route = express_1.default.Router();
route.post("/verification", VerificationController_1.Otp_Verification); //step-2
route.post("/new_password", VerificationController_1.Reset_password); //step-3
// 
route.post("/forget-password", VerificationController_1.forget_password); //step-1
route.post("/password", VerificationController_1.resendPassword);
exports.default = route;
