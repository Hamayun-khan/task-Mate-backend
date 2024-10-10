import { Router } from 'express';
import {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
} from '@controllers/user.controller';
import upload from 'middleware/multer.middleware';
import { verifyJwt } from 'middleware/auth.middleware';

const router = Router();

router.route('/register').post(
  upload.fields([
    { name: 'avatar', maxCount: 1 },
    { name: 'coverImage', maxCount: 1 },
  ]),
  registerUser
);

router.route('/login').post(loginUser);

// secure routes
router.route('/logout').post(verifyJwt, logoutUser);
router.route('/refresh-token').post(refreshAccessToken);

export default router;
