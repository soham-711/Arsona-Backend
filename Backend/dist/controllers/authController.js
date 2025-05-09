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
exports.loginUser = exports.registerUser = void 0;
const userModel_1 = __importDefault(require("../models/userModel"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const registerUser = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        console.log(req.body);
        const { name, email, password, confirmPassword, MobileNumber } = req.body;
        console.log(confirmPassword, password, email, name, MobileNumber);
        // Check if all fields are provided
        if (!name || !email || !password || !confirmPassword || !MobileNumber) {
            return res.status(400).send({ message: 'All fields are required', data: null, success: false });
        }
        // Check if passwords match
        if (password !== confirmPassword) {
            return res.status(400).send({ message: 'Passwords do not match', data: null, success: false });
        }
        // Check if user already exists
        const findUser = yield userModel_1.default.findOne({ email });
        if (findUser) {
            return res.status(409).send({ message: 'User already exists', data: null, success: false });
        }
        // Create new user
        const newUser = yield userModel_1.default.create({ name, email, password, MobileNumber });
        return res.status(200).send({ message: "User registered successfully", data: newUser, success: true });
    }
    catch (error) {
        console.error("Registration Error:", error);
        return res.status(500).send({ message: 'Internal Server Error', data: null, success: false });
    }
});
exports.registerUser = registerUser;
const loginUser = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, password } = req.body;
        console.log(req.body);
        if (!email || !password) {
            return res.status(400).send({ message: 'Email and password are required', data: null, success: false });
        }
        const userFound = yield userModel_1.default.findOne({ email }).select('+password');
        if (!userFound) {
            return res.status(404).send({ message: 'User not found', data: null, success: false });
        }
        if (userFound.password !== password) {
            return res.status(401).send({ message: 'Invalid password', data: null, success: false });
        }
        const token = jsonwebtoken_1.default.sign({ email: userFound.email, id: userFound._id }, process.env.JWT_SECRET || 'secret', { expiresIn: '24h' });
        res.cookie("access_token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', // true on Render
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // lowercase!
            maxAge: 24 * 60 * 60 * 1000, // 1 day
        });
        return res.status(200).send({
            message: 'Login successful',
            data: {
                id: userFound._id,
                name: userFound.name,
                email: userFound.email,
            },
            success: true
        });
    }
    catch (error) {
        console.error('Error during login:', error);
        return res.status(500).send({ message: 'Internal Server Error', data: null, success: false });
    }
});
exports.loginUser = loginUser;
