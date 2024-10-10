import { Request, Response, NextFunction } from 'express';
import apiResponse from '@utils/apiResponse';
import ApiError from '@utils/apiError';
import { Task } from '@models/Task.model';
import { asyncHandler } from '@utils/asyncHandler';

// Create a new task
const createTask = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    console.log('Request Body:', req.body); // Log the request body
    console.log('User from token:', req.user); // Log the user information from token

    const { title, description, status, dueDate } = req.body;

    // Get userId from the decoded token payload
    const userId = req.user?.id; // Make sure to use the correct key based on your JWT payload

    if (!userId) {
      throw new ApiError(401, 'Unauthorized');
    }

    // Create a new task
    const task = await Task.create({
      title,
      description,
      status,
      dueDate,
      user: userId,
    });

    return res
      .status(201)
      .json(new apiResponse(201, 'Task created successfully', task));
  }
);
// Get all tasks
const getTasks = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const userId = req.user?.id;

    if (!userId) {
      throw new ApiError(401, 'Unauthorized');
    }

    const tasks = await Task.find({ user: userId });

    return res
      .status(200)
      .json(new apiResponse(200, 'Tasks fetched successfully', tasks));
  }
);

// update a task
const updateTask = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { id } = req.params;
    const { title, description, status, dueDate } = req.body;

    const task = await Task.findById(id);

    if (!task) {
      throw new ApiError(404, 'Task not found');
    }

    if (task.user?.toString() !== req.user?.id.toString()) {
      throw new ApiError(401, 'Unauthorized');
    }

    task.title = title || task.title;
    task.description = description || task.description;
    task.status = status !== undefined ? status : task.status;
    task.dueDate = dueDate || task.dueDate;

    await task.save();

    return res
      .status(200)
      .json(new apiResponse(200, 'Task updated successfully', task));
  }
);

// delete a task
const deleteTask = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { id } = req.params;

    const task = await Task.findById(id);

    if (!task) {
      throw new ApiError(404, 'Task not found');
    }

    if (task.user?.toString() !== req.user?.id.toString()) {
      throw new ApiError(401, 'Unauthorized');
    }

    await task.deleteOne();

    return res
      .status(200)
      .json(new apiResponse(200, 'Task deleted successfully', task));
  }
);

export { createTask, getTasks, updateTask, deleteTask };
