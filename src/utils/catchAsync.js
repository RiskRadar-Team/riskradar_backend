/** to replace the uses of try catch in each contoller funtion */
/** here fn stands for controller function */
const catchAsync = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch((error) => {
      next(error);
      /** here line number 6 tells the express server to go directly to error-handling middleware */
    });
  };
};

export default catchAsync;
