import { Request, Response } from 'express';
import jwt from "jsonwebtoken";

import userModel from '../models/userModel';

export const validation=async(req:Request,res:Response):Promise<any>=>{

const {Token} = req.body;
console.log(Token);

  if (!Token) {
    return res.status(401).send({ message: "Token not found", user: null ,success:false});
  }


  try {
    const decoded = jwt.verify(Token, process.env.JWT_SECRET || 'secret') as jwt.JwtPayload;
    const userData = await userModel.findById(decoded.id);
    if (!userData) {
      return res.status(404).send({ message: "User not found", user: null ,success:false});
    }
    return res.status(200).send({ message: "Token valid", user: decoded,success:true });
  } catch (error) {
    return res.status(401).send({ message: "Token invalid or expired", user: null,success:false });
  }
}