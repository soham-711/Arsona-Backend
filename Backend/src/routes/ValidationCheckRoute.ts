import express from 'express'
import { validation } from '../controllers/ValidationController'
const route=express.Router()
route.get("/validationCheck",validation)
export default  route