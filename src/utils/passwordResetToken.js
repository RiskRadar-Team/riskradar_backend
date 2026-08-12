import jwt from "jsonwebtoken";
import ApiError from "./ApiError.js";

/**
 * Generate a short-lived password reset authorization token.
 *
 * This token is issued only after the user's OTP
 * has been successfully verified.
 */
export function generatePasswordResetToken(userId) {
  if (!userId) {
    throw new ApiError(
      500,
      "User ID is required to generate password reset token.",
    );
  }

  return jwt.sign(
    {
      id: userId,
      type: "PASSWORD_RESET",
    },
    process.env.PASSWORD_RESET_TOKEN_SECRET,
    {
      expiresIn: process.env.PASSWORD_RESET_TOKEN_EXPIRES_IN || "10m",
    },
  );
}

/**
 * Verify password reset authorization token.
 */
export function verifyPasswordResetToken(token) {
  try {
    const payload = jwt.verify(token, process.env.PASSWORD_RESET_TOKEN_SECRET);

    /*
     * Make sure this token was specifically created
     * for password reset only.
     */
    if (payload.type !== "PASSWORD_RESET") {
      throw new Error("Invalid password reset token type.");
    }

    return payload;
  } catch (error) {
    throw new ApiError(400, "Invalid or expired password reset token.");
  }
}
