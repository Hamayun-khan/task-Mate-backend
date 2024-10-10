class ApiError extends Error {
  public statusCode: number;
  public isOperational: boolean;
  public details?: any;

  constructor(statusCode: number, message: string, details?: any) {
    super(message);
    this.statusCode = statusCode;
    this.message = message;
    this.isOperational = true;
    this.details = details;

    this.name = this.constructor.name;

    Error.captureStackTrace(this, this.constructor);
  }
}

export default ApiError;
