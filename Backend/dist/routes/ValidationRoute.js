"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const ValidationController_1 = require("../controllers/ValidationController");
const route = express_1.default.Router();
route.get("/validationCheck", ValidationController_1.validation);
exports.default = route;
