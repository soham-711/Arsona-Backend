import mongoose, { Schema, Document } from "mongoose";

export interface IUser extends Document {
  name: string;
  password: string;
  email: string;
  MobileNumber:string;
  token: string;
}

const userSchema: Schema = new Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
      select: false,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    MobileNumber:{
   type:String,
   required:true
    },
    token: {
      type: String,
    },
  },
  { timestamps: true }
);

export default mongoose.model<IUser>("User", userSchema);
