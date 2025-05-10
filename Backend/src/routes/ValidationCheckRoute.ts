import express from 'express'
import { validation } from '../controllers/ValidationController'
const route=express.Router()
route.post("/validationCheck",validation)
export default  route