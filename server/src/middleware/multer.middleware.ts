import multer, { StorageEngine } from 'multer';
import path from 'path';
import { Request } from 'express';

// Define allowed file types
const allowedFileTypes = ['image/jpeg', 'image/png', 'image/gif'];

// Custom file filter to validate file types
const fileFilter = (
  req: Request,
  file: Express.Multer.File,
  cb: multer.FileFilterCallback
) => {
  if (allowedFileTypes.includes(file.mimetype)) {
    cb(null, true); // Accept file
  } else {
    cb(new Error('Invalid file type. Only JPEG, PNG, and GIF are allowed.'));
  }
};

// Define storage configuration
const storage: StorageEngine = multer.diskStorage({
  destination: (
    req: Request,
    file: Express.Multer.File,
    cb: (error: Error | null, destination: string) => void
  ) => {
    cb(null, path.join(__dirname, '../../public/temp'));
  },
  filename: (
    req: Request,
    file: Express.Multer.File,
    cb: (error: Error | null, filename: string) => void
  ) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    cb(
      null,
      `${file.fieldname}-${uniqueSuffix}${path.extname(file.originalname)}`
    ); // Append timestamp to file name to avoid conflicts
  },
});

// Create multer instance with storage and file validation
const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // Max file size: 5 MB
  },
  fileFilter,
});

export default upload;
