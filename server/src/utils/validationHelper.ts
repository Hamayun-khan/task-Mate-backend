import { body } from 'express-validator';

const registeredUserValidation = [
  body('name').notEmpty().withMessage('Name is required'),
  body('email').isEmail().withMessage('Must be a valid email address'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long'),
  body('fullName').notEmpty().withMessage('Full name is required'),
  body('avatar').notEmpty().withMessage('Avatar is required'),
];

export const taskValidation = [
  body('title')
    .notEmpty()
    .withMessage('Title is required') // Matches the model's 'required' field for title
    .trim(), // Ensures no extra whitespace

  body('description')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Description should not exceed 500 characters'), // Matches the schema's optional and trim nature

  body('status')
    .notEmpty()
    .withMessage('Status is required') // Required based on the model
    .isIn(['Pending', 'In Progress', 'Completed'])
    .withMessage('Status must be one of Pending, In Progress, or Completed'), // Enum check for valid values

  body('dueDate')
    .optional() // Due date is not mandatory, but can be validated when provided
    .isISO8601()
    .withMessage('Due date must be a valid date'),
];

export default registeredUserValidation;
