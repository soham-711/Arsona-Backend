import mongoose from 'mongoose';

const connectDB = async () => {
  try {
    await mongoose.connect('mongodb+srv://sohambiswas716:AwzaSaBwr2vOekeV@cluster0.1agr7.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0');  // Replace later
    console.log('MongoDB connected');
  } catch (error) {
    console.error('MongoDB connection failed', error);
    process.exit(1);
  }
};

export default connectDB;
