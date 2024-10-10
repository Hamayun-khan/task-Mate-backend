import mongoose from 'mongoose';
import { DB_NAME } from './config';

const connectDB = async () => {
  try {
    const uri = process.env.MONGO_URI;
    if (!uri) throw new Error('URI not found');

    const connectionInstance = await mongoose.connect(uri, {
      dbName: DB_NAME,
    });
    console.log(
      `\nMongoDB Connected!! DB HOST:${connectionInstance.connection.host}`
    );
  } catch (error: string | any) {
    console.error('ERROR connecting to mongoDB:', error.message);
    process.exit(1);
  }
};

export default connectDB;
