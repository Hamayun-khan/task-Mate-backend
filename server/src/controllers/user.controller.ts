import { asyncHandler } from '@utils/asyncHandler';
import { Request, Response } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import apiResponse from '@utils/apiResponse';
import ApiError from '@utils/apiError';
import { User } from '@models/User.model';
import { validationResult } from 'express-validator';
import uploadToCloudinary from '@utils/cloudinary';

// generate access token and refresh token
export const generateAccessTokenAndRefreshToken = async (
  userId: string
): Promise<{ accessToken: string; refreshToken: string } | null> => {
  try {
    const user = await User.findById(userId);
    if (!user) {
      console.log('User not found');
      throw new ApiError(404, 'User not found');
    }
    console.log('Access Token Secret:', process.env.ACCESS_TOKEN_SECRET);
    const accessToken = user.getAccessToken();
    const refreshToken = user.getRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error: any) {
    console.error('Error in token generation:', error);
    throw new ApiError(500, 'Internal server error');
  }
};

// Register user controller
export const registerUser = asyncHandler(
  async (req: Request, res: Response) => {
    // Validate request input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ApiError(400, 'Validation failed', errors.array());
    }

    const { name, fullName, email, password } = req.body;

    console.log(name, fullName, email, password);
    // Check if user already exists by email or userId
    const existingUser = await User.findOne({ $or: [{ email }, { name }] });
    if (existingUser) {
      throw new ApiError(
        400,
        'User with this email or fullName already exists'
      );
    }

    let avatarUrl = req.body.avatar || null;
    let coverImageUrl = req.body.coverImage || null;

    const files = req.files as { [fieldname: string]: Express.Multer.File[] };

    // If files exist (i.e., form-data was used)
    if (files && files['avatar']) {
      const avatarFile = files['avatar'][0];
      const uploadResult = await uploadToCloudinary(avatarFile.path);
      avatarUrl = uploadResult.secure_url;
    }

    if (files && files['coverImage']) {
      const coverImageFile = files['coverImage'][0];
      const uploadResult = await uploadToCloudinary(coverImageFile.path);
      coverImageUrl = uploadResult.secure_url;
    }

    // Create and save new user to the database (without manual password hashing)
    const newUser = new User({
      name,
      fullName,
      email,
      password, // plain password, will be hashed in the pre-save hook
      avatar: avatarUrl,
      coverImage: coverImageUrl,
      role: 'user',
    });

    await newUser.save();

    // Generate access token and refresh token
    const tokenData = await generateAccessTokenAndRefreshToken(newUser._id);
    if (!tokenData) {
      throw new ApiError(500, 'Failed to generate tokens');
    }

    const { accessToken, refreshToken } = tokenData;

    // Send success response with tokens
    return res.status(201).json(
      new apiResponse(201, 'User registered successfully', {
        user: newUser,
        accessToken,
        refreshToken,
      })
    );
  }
);

export const loginUser = asyncHandler(async (req: Request, res: Response) => {
  const { email, password, name } = req.body;

  // Check if user exists by email or name
  if (!email && !name) {
    throw new ApiError(400, 'Email or name is required');
  }

  const user = await User.findOne({ $or: [{ email }, { name }] });
  if (!user) {
    throw new ApiError(404, 'User not found');
  }

  // Password check
  const isMatch = await user.matchPassword(password);
  if (!isMatch) {
    throw new ApiError(401, 'Invalid credentials');
  }

  const tokenData = await generateAccessTokenAndRefreshToken(user._id);
  if (!tokenData) {
    throw new ApiError(500, 'Failed to generate tokens');
  }

  const { accessToken, refreshToken } = tokenData;

  // Fetch the user data without the password and refreshToken fields
  const loggedInUser = await User.findById(user._id).select(
    '-password -refreshToken'
  );

  const options = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days expiry
  };

  return res
    .status(200)
    .cookie('accessToken', accessToken, options)
    .cookie('refreshToken', refreshToken, options)
    .json(
      new apiResponse(200, 'User logged in successfully', {
        user: loggedInUser,
        accessToken,
        refreshToken,
      })
    );
});

export const logoutUser = asyncHandler(async (req: Request, res: Response) => {
  const options = {
    httpOnly: true,
    expires: new Date(0),
  };
  return res
    .status(200)
    .cookie('accessToken', '', options)
    .cookie('refreshToken', '', options)
    .json(new apiResponse(200, 'User logged out successfully'));
});

interface ExtendedJwtPayload extends JwtPayload {
  id?: string; // Add the 'id' property expected from the JWT
}

// Controller for refreshing access token
export const refreshAccessToken = asyncHandler(
  async (req: Request, res: Response) => {
    // Check if refreshToken is present in cookies first, then from request body
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;

    // Check if refresh token is present
    if (!refreshToken) {
      throw new ApiError(401, 'Refresh token not provided');
    }

    try {
      // Verify the refresh token
      const decoded = jwt.verify(
        refreshToken,

        process.env.REFRESH_TOKEN_SECRET!
      ) as ExtendedJwtPayload;

      // Check if the user still exists and refresh token matches
      const user = await User.findById(decoded.id);
      if (!user || user.refreshToken !== refreshToken) {
        throw new ApiError(403, 'Invalid refresh token');
      }

      console.log('Stored Refresh Token:', user.refreshToken);

      console.log('Received Refresh Token:', refreshToken);

      // Generate a new access token
      const newAccessToken = user.getAccessToken();

      // Send the new access token to the client
      return res.status(200).json(
        new apiResponse(200, 'Access token refreshed successfully', {
          accessToken: newAccessToken,
        })
      );
    } catch (error) {
      // Improved error handling with more specific cases
      if (error instanceof jwt.TokenExpiredError) {
        throw new ApiError(401, 'Refresh token has expired');
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw new ApiError(403, 'Invalid refresh token');
      }
      // Handle other potential errors that may arise
      throw new ApiError(500, 'Internal server error');
    }
  }
);
