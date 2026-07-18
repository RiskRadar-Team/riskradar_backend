import jwt from "jsonwebtoken";
import ApiError from "./ApiError.js";

export const generateAccessToken = (user) => {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_ACCESS_EXPIRES_IN,
    },
  );
};

/**Generate Refresh Token */
export const generateRefreshToken = (user) => {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
    },
    process.env.JWT_SECRET_REFRESH,
    {
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
    },
  );
};

/**Verify access token */
export const verifyAccessToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    // console.log("JWT ERROR:", error);
    throw new ApiError(401, "Invalid or expired access token.");
  }
};

/**Verify Refresh Token */

export const verifyRefreshToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET_REFRESH);
  } catch (error) {
    throw new ApiError(401, "Invalid or expired refresh token.");
  }
};
