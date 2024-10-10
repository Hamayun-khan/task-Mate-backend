import mongoose, { Schema, Document } from 'mongoose';
import mongooseAggregatePaginate from 'mongoose-aggregate-paginate-v2';
export interface ITask extends Document {
  title: string;
  description: string;
  status: string;
  dueDate: Date;
  user: Schema.Types.ObjectId;
}

const taskSchema: Schema<ITask> = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },
    description: {
      type: String,
      trim: true,
    },
    status: {
      type: String,
      enum: ['Pending', 'In Progress', 'Completed'],
      default: 'Pending',
    },
    dueDate: {
      type: Date,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
  },
  { timestamps: true }
);

taskSchema.plugin(mongooseAggregatePaginate);

export const Task = mongoose.model<ITask>('Task', taskSchema);
