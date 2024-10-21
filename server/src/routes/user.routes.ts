import { Router } from 'express';
import {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  forgotPassword,
  resetPassword,
  getResetToken,
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

router.route('/forgot-password').post(forgotPassword); // Route to request a password reset

// GET route to handle the link click from an email in a browser
router.route('/reset-password/:token').get((req, res) => {
  const resetToken = req.params.token;
  res.send(`
    <html>
      <body>
        <h1>Password Reset</h1>
        <p>If you are using a mobile device, please open the app to reset your password.</p>
        <p>If you have the app installed, click this link to open the app: <a href="taskmate://reset-password/${resetToken}">Reset Password in App</a></p>
      </body>
    </html>
  `);
});

// POST route to handle the actual password reset form submission
router.route('/reset-password/:token').post(resetPassword);

// Route to handle web-based reset token retrieval
router.route('/reset-password-web/:resetId').get(getResetToken);

export default router;
