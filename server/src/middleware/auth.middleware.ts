import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload, Secret } from 'jsonwebtoken';
import ApiError from '@utils/apiError';

// Extend the Request interface to include the user property
interface CustomRequest extends Request {
  user?: JwtPayload; // Define the user property to hold the decoded JWT payload
}

export const verifyJwt = (
  req: CustomRequest,
  _: Response,
  next: NextFunction
) => {
  const token =
    req.cookies.accessToken || req.headers['authorization']?.split(' ')[1]; // Check both cookie and Authorization header
  console.log('Token:', token); // Log the received token
  // If token is not found, respond with an error
  if (!token) {
    return next(new ApiError(401, 'Access token not found'));
  }

  // Verify the token
  jwt.verify(
    token,
    process.env.ACCESS_TOKEN_SECRET! as Secret,
    (err: any, decoded: any) => {
      if (err) {
        console.log('Token verification error:', err); // Log any verification error
        // Handle different JWT errors for better error handling
        if (err instanceof jwt.TokenExpiredError) {
          return next(new ApiError(401, 'Access token has expired'));
        }
        if (err instanceof jwt.JsonWebTokenError) {
          return next(new ApiError(403, 'Invalid access token'));
        }
        return next(new ApiError(403, 'Access token verification failed'));
      }
      console.log('Decoded token payload:', decoded);
      // Attach decoded user information to the request object
      req.user = decoded; // user contains the payload (e.g., id, email)

      next(); // Proceed to the next middleware or route handler
    }
  );
};
