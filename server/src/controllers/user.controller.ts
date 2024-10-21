import { asyncHandler } from '@utils/asyncHandler';
import jwt, { JwtPayload } from 'jsonwebtoken';
import apiResponse from '@utils/apiResponse';
import ApiError from '@utils/apiError';
import { User } from '@models/User.model';
import { validationResult } from 'express-validator';
import uploadToCloudinary from '@utils/cloudinary';
import { Request, Response } from 'express';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import bcrypt from 'bcrypt';

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

export const forgotPassword = asyncHandler(
  async (req: Request, res: Response) => {
    console.log('Forgot password request received:', req.body);
    const { email } = req.body;

    // Check if the user exists
    const user = await User.findOne({ email });
    console.log('User found:', user ? 'Yes' : 'No');
    if (!user) {
      throw new ApiError(404, 'User not found');
    }

    // Generate a password reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    console.log('Reset token generated:', resetToken); // Log the plain token

    const resetTokenHash = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    console.log('Reset token hash:', resetTokenHash); // Log the hashed token

    // Set token expiry time (1 hour)
    user.resetPasswordToken = resetTokenHash;
    user.resetPasswordExpires = new Date(Date.now() + 3600000); // 1 hour from now
    await user.save({ validateBeforeSave: false });
    console.log('User updated with reset token');

    console.log('CLIENT_URL:', process.env.CLIENT_URL);
    // Create reset URL
    const resetUrl = `${process.env.CLIENT_URL}/api/v1/user/reset-password/${resetToken}`;

    console.log('Reset URL:', resetUrl);

    // Send email
    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: process.env.EMAIL_FROM,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const mailOptions = {
      to: email,
      from: process.env.EMAIL_FROM,
      subject: 'Password Reset',
      text: `You requested a password reset. Click the link to reset your password: ${resetUrl}`,
    };

    try {
      await transporter.sendMail(mailOptions);
      console.log('Password reset email sent successfully');
      return res
        .status(200)
        .json(new apiResponse(200, 'Password reset link sent to your email'));
    } catch (error) {
      console.error('Error sending email:', error);
      throw new ApiError(500, 'Error sending email. Please try again later.');
    }
  }
);

export const getResetToken = asyncHandler(
  async (req: Request, res: Response) => {
    console.log('Get reset token request received:', req.params);
    const { resetId } = req.params;
    const user = await User.findOne({
      resetPasswordId: resetId,
      resetPasswordExpires: { $gt: Date.now() },
    });

    console.log('User found for reset token:', user ? 'Yes' : 'No');
    if (!user) {
      throw new ApiError(400, 'Invalid or expired reset ID');
    }

    console.log('Reset token retrieved:', user.resetPasswordToken);
    return res.json({ resetToken: user.resetPasswordToken });
  }
);

export const resetPassword = asyncHandler(
  async (req: Request, res: Response) => {
    console.log('Reset password request received:', req.body);
    const { token } = req.params; // Extract token from URL parameters
    const { newPassword, confirmPassword } = req.body;

    // Check if passwords match
    if (newPassword !== confirmPassword) {
      console.error('Password mismatch:', { newPassword, confirmPassword });
      throw new ApiError(400, 'Passwords do not match');
    }

    // Hash the token to compare with the stored hash
    const resetTokenHash = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');
    console.log('Hashed reset token:', resetTokenHash);

    // Find the user with the matching reset token and check if it has expired
    const user = await User.findOne({
      resetPasswordToken: resetTokenHash,
      resetPasswordExpires: { $gt: Date.now() }, // Ensure token has not expired
    });

    if (!user) {
      console.error('User not found for token:', resetTokenHash);
      throw new ApiError(400, 'Invalid or expired token');
    }

    // Log existing hashed password for comparison
    console.log('Current hashed password in DB:', user.password);

    // Hash the new password before saving it
    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    console.log('New hashed password to be saved:', newPasswordHash);

    // Save the new password
    user.password = newPasswordHash; // Update with new hashed password
    user.resetPasswordToken = undefined; // Clear the reset token
    user.resetPasswordExpires = undefined; // Clear the expiry

    // Save the updated user information
    await user.save();
    console.log(`Password reset for user: ${user.email}`);

    return res
      .status(200)
      .json(new apiResponse(200, 'Password has been successfully reset'));
  }
);
