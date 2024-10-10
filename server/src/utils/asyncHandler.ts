export const asyncHandler =
  (requestHandler: Function) => async (req: any, res: any, next: any) => {
    try {
      return await Promise.resolve(requestHandler(req, res, next));
    } catch (err) {
      console.error('Error caught in asyncHandler:', err);
      next(err);
    }
  };
