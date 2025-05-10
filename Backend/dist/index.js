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
// server.ts
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const dotenv_1 = __importDefault(require("dotenv"));
const db_1 = __importDefault(require("./config/db"));
const authRoutes_1 = __importDefault(require("./routes/authRoutes"));
// import userModel from "./models/userModel";
// import jwt from "jsonwebtoken";
const cookie_parser_1 = __importDefault(require("cookie-parser"));
// import { sendOtpEmail } from "./utils/sendEmail";
const ValidationCheckRoute_1 = __importDefault(require("./routes/ValidationCheckRoute"));
const verificationRoute_1 = __importDefault(require("./routes/verificationRoute"));
dotenv_1.default.config();
(0, db_1.default)();
const app = (0, express_1.default)();
// CORS setup
app.use((0, cors_1.default)({
    origin: '*', // or specific mobile origin if known
    credentials: true, // allow cookies
}));
// ! when you sending request from frontend send withCredentials True with data
app.use(express_1.default.json());
app.use((0, cookie_parser_1.default)());
//! home directory
app.get('/', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    return res.status(200).send({ message: "Welcome to Backend" });
}));
// register-login
app.use("/arsona/auth", authRoutes_1.default);
// forget password,otp-verification,
app.use("/arsona/otp-verification", verificationRoute_1.default);
//validation routes
app.use("/validate", ValidationCheckRoute_1.default);
//resend password
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
