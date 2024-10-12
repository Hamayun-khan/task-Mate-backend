import express from 'express';
import { facebookAuth, googleCallback } from '@controllers/user.controller';
const router = express.Router();
router.get('/test', (req, res) => {
  console.log('Test route hit!');
  res.status(200).send('Test successful');
});
router.route('/facebook').post(facebookAuth);
router.route('/google/callback').post(googleCallback);

export default router;
