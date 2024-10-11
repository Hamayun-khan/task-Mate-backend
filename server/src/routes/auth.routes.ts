import express from 'express';
import { googleAuth, facebookAuth } from '@controllers/user.controller';

const router = express.Router();

router.route('/google').post(googleAuth);
router.route('/facebook').post(facebookAuth);

export default router;
