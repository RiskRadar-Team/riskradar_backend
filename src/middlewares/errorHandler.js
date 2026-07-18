const errorHandler = (error, request, response, next) => {
  console.log(error);

  const statusCode = error.statusCode || 500;

  response.status(statusCode).json({
    success: false,
    message: error.message || "Internal Server Error",
    errors: error.errors || [],
  });
};
export default errorHandler;
