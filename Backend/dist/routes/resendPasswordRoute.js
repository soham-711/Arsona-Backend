"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const resendPasswordController_1 = require("../controllers/resendPasswordController");
const router = express_1.default.Router();
router.post("/password", resendPasswordController_1.resendPassword);
exports.default = router;
