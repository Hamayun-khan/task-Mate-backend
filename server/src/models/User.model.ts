import mongoose, { Schema, Document } from 'mongoose';
import jwt, { SignOptions } from 'jsonwebtoken';
import bcrypt from 'bcrypt';

export interface IUser extends Document {
  _id: string;
  name: string;
  fullName: string;
  email: string;
  password: string;
  userId: string;
  avatar: string;
  coverImage?: string;
  role: 'admin' | 'user';
  refreshToken?: string;
  isModified(path: string): boolean;
  tasks: Schema.Types.ObjectId[];
  matchPassword: (enteredPassword: string) => Promise<boolean>;
  getRefreshToken: () => string;
  getAccessToken: () => string;
}

const userSchema: Schema<IUser> = new mongoose.Schema(
  {
    name: {
      type: String,
      unique: true,
      required: [true, 'please tell your name'],
      trim: true,
    },
    fullName: {
      type: String,
      trim: true,
    },
    email: {
      type: String,
      unique: true,
      required: [true, 'please provide your email'],
      trim: true,
      lowercase: true,
    },
    password: {
      type: String,
      unique: true,
      required: [true, 'please type your password'],
    },
    avatar: {
      type: String,
      default: null,
    },
    coverImage: {
      type: String,
    },

    role: {
      type: String,
      enum: ['admin', 'user'],
      default: 'user',
    },
    refreshToken: {
      type: String,
    },
    tasks: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Task',
      },
    ],
  },
  { timestamps: true }
);

userSchema.pre<IUser>('save', async function (next): Promise<void> {
  if (!this.isModified('password')) {
    return next();
  }
  try {
    this.password = await bcrypt.hash(this.password as string, 10);

    next();
  } catch (err: any) {
    console.error('Error in pre-save hook:', err);
    next(err); // Pass the error to the next middleware
  }
});

userSchema.methods.matchPassword = async function (
  enteredPassword: string
): Promise<boolean> {
  const isMatch = await bcrypt.compare(
    enteredPassword,
    this.password as string
  );

  return isMatch;
};

userSchema.methods.getAccessToken = function (): string {
  const user = this as IUser;

  // Validate environment variables
  const secret = process.env.ACCESS_TOKEN_SECRET;
  const expiry = process.env.ACCESS_TOKEN_EXPIRY;

  if (!secret || !expiry) {
    throw new Error('Access token configuration is missing');
  }

  const payload = {
    id: user._id,
    email: user.email,
    name: user.name,
    fullName: user.fullName,
  };
  console.log('Access Token Secret:', process.env.ACCESS_TOKEN_SECRET);
  const options: SignOptions = { expiresIn: expiry };

  return jwt.sign(payload, secret, options);
};

userSchema.methods.getRefreshToken = function (): string {
  const user = this as IUser;

  // Validate environment variables
  const secret = process.env.REFRESH_TOKEN_SECRET;
  const expiry = process.env.REFRESH_TOKEN_EXPIRY;

  if (!secret || !expiry) {
    throw new Error('Refresh token configuration is missing');
  }

  const payload = {
    id: user._id,
    email: user.email,
  };

  const options: SignOptions = { expiresIn: expiry };

  return jwt.sign(payload, secret, options);
};

export const User = mongoose.model<IUser>('User', userSchema);
