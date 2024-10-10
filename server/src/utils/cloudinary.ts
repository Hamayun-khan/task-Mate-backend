import { v2 as cloudinary } from 'cloudinary';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import ApiError from '@utils/apiError'; // Import your custom ApiError

// Load environment variables
dotenv.config();

// Cloudinary configuration setup
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Function to upload a file to Cloudinary
const uploadToCloudinary = async (filePath: string): Promise<any> => {
  const absoluteFilePath = path.resolve(filePath); // Convert to absolute path

  // Check if the file exists before attempting upload
  if (!fs.existsSync(absoluteFilePath)) {
    throw new ApiError(404, 'File not found at the specified path'); // Throw custom ApiError
  }

  // Check if environment variables are correctly set
  if (
    !process.env.CLOUDINARY_CLOUD_NAME ||
    !process.env.CLOUDINARY_API_KEY ||
    !process.env.CLOUDINARY_API_SECRET
  ) {
    throw new ApiError(
      500,
      'Cloudinary configuration is not set properly in environment variables'
    );
  }

  try {
    const response = await cloudinary.uploader.upload(absoluteFilePath, {
      resource_type: 'auto', // Automatically detect the file type
    });

    // File upload success: remove the file locally after upload
    fs.unlinkSync(absoluteFilePath);
    console.log('File uploaded to Cloudinary successfully.');
    console.log('Cloudinary URL:', response.secure_url); // Use secure URL for HTTPS

    // Return the full response
    return response;
  } catch (error) {
    console.error('Error during Cloudinary upload:', error);

    // Attempt to remove the file locally even if the upload fails
    try {
      fs.unlinkSync(absoluteFilePath);
      console.log('File deleted locally after upload failure.');
    } catch (unlinkError) {
      console.error('Error deleting the file locally:', unlinkError);
    }

    // Wrap and rethrow the error as ApiError
    throw new ApiError(500, 'Failed to upload the file to Cloudinary', error);
  }
};

export default uploadToCloudinary;
