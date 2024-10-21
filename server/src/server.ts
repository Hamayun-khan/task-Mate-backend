import dotenv from 'dotenv';
import app from 'app';
import connectDB from 'db/database';
import path from 'path';

require('dotenv').config();
console.log('Access Token Secret:', process.env.ACCESS_TOKEN_SECRET);

dotenv.config({
  path: path.resolve(__dirname, '../.env'),
});
require('dotenv').config();


console.log('Access Token Secret:', process.env.ACCESS_TOKEN_SECRET);

console.log('Cloudinary Cloud Name:', process.env.CLOUDINARY_CLOUD_NAME);
console.log('Cloudinary API Key:', process.env.CLOUDINARY_API_KEY);
console.log('Cloudinary API Secret:', process.env.CLOUDINARY_API_SECRET);
const serverStart = async () => {
  await connectDB();

  const port = process.env.PORT || 3000;

  app.listen(port, () => {
    console.log('Server running on port', port);
  });
};

serverStart();
