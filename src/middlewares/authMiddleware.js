import UserModel from "../models/userModel.js";

import ApiError from "../utils/ApiError.js";
import catchAsync from "../utils/catchAsync.js";

import { verifyAccessToken } from "../utils/jwt.js";

const authMiddleware = catchAsync(async (request, response, next) => {
  const authHeader = request.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new ApiError(401, "Access denied. No access token provided.");
  }

  const accessToken = authHeader.split(" ")[1];
  // console.log("Access Token:", accessToken);
  const payload = verifyAccessToken(accessToken);
  // console.log("Payload:", payload);
  const user = await UserModel.findById(payload.id);

  if (!user) {
    throw new ApiError(401, "Invalid access token.");
  }

  if (!user.is_active) {
    throw new ApiError(403, "Your account has been deactivated.");
  }

  delete user.password;

  request.user = user;

  next();
});

export default authMiddleware;
