import { Router } from 'express';
import {
  getTasks,
  createTask,
  updateTask,
  deleteTask,
} from '@controllers/task.controller';
import { verifyJwt } from 'middleware/auth.middleware';
import { taskValidation } from '@utils/validationHelper';

const router = Router();

router.route('/get').get(verifyJwt, getTasks);
router.route('/create').post(verifyJwt, taskValidation, createTask);
router.route('/:id').put(verifyJwt, taskValidation, updateTask);
router.route('/:id').delete(verifyJwt, deleteTask);

export default router;
