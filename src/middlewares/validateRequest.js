import { validationResult } from "express-validator";
import ApiError from "../utils/ApiError.js";

const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  // console.log(req);
  if (!errors.isEmpty()) {
    throw new ApiError(400, "Validation failed.", errors.array());
  }

  next();
};

export default validateRequest;
