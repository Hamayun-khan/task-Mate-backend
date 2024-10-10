import { Request, Response, NextFunction } from 'express';
import ApiError from '@utils/apiError';

export const globalErrorHandler = (
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (err instanceof ApiError) {
    return res.status(err.statusCode).json({
      message: err.message,
      details: err.details || null,
      success: false,
    });
  }

  console.log('Unexpected error:', err);

  return res.status(500).json({
    message: 'Internal server error',
    details: null,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
};
