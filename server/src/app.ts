import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import path from 'path';
import { globalErrorHandler } from '@utils/global.error';
import morgan from 'morgan';
const app = express();

app.use(
  cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
  })
);

app.use(morgan('dev'));
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(
  '/.well-known',
  express.static(path.join(__dirname, '../../.well-known'))
); // Adjust the path here
app.use(cookieParser());

// Routes implementation
import userRoute from './routes/user.routes';
import taskRoute from './routes/tasks.routes';

app.use('/api/v1/user', userRoute);
app.use('/api/v1/task', taskRoute);

app.use(globalErrorHandler);

export default app;
