import UserModel from "../models/userModel.js";
import AuthModel from "../models/authModel.js";
import ApiError from "../utils/ApiError.js";
import {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
} from "../utils/jwt.js";
import { comparePassword, hashPassword } from "../utils/password.js";
/**
 * imports for forget password
 */
import PasswordResetOtpModel from "../models/passwordResetOtpModel.js";

import {
  generateOtp,
  hashOtp,
  getOtpExpiry,
} from "../utils/passwordResetOtp.js";

import { sendPasswordResetOtpEmail } from "../utils/email.js";
import {
  generatePasswordResetToken,
  verifyPasswordResetToken,
} from "../utils/passwordResetToken.js";
class AuthService {
  /**Register new user */
  static async register(userData) {
    const { full_name, email, password } = userData;

    //check if email already exist
    const existingUser = await UserModel.findByEmail(email);
    if (existingUser) {
      throw new ApiError(409, "An user with this email already exist.");
    }
    //hash_password
    const hashedPassword = await hashPassword(password);
    //create user
    const user = await UserModel.create(
      full_name,
      email,
      hashedPassword,
      "USER",
    );

    //Generate token
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    //Calculate Refresh token expiry
    const expires_at = new Date(
      Date.now() + Number(process.env.REFRESH_TOKEN_EXPIRES_MS),
    );
    //Save Refresh Token
    const userId = user.id;
    await AuthModel.createRefreshToken(userId, refreshToken, expires_at);

    //remove sensitive information
    delete user.password;
    return { accessToken, refreshToken, user };
  }

  /**User Login */
  static async login(loginData) {
    const { email, password } = loginData;
    //find user by email
    const user = await UserModel.findByEmail(email);

    if (!user) {
      throw new ApiError(401, "Invalid email or password.");
    }
    //check account is active or not
    if (!user.is_active) {
      throw new ApiError(
        403,
        "Your account has been deactivated or removed. Please contact support",
      );
    }
    const existingPassword = user.password;

    //compare password
    const isPasswordCorrect = await comparePassword(password, existingPassword);
    if (!isPasswordCorrect) {
      throw new ApiError(401, "Invalid email or password");
    }
    // Generate tokens
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    // Refresh token expiry
    const expires_at = new Date(
      Date.now() + Number(process.env.REFRESH_TOKEN_EXPIRES_MS),
    );
    //Save Refresh Token
    const userId = user.id;
    await AuthModel.createRefreshToken(userId, refreshToken, expires_at);

    //update last login details
    await UserModel.updateLastLogin(userId);
    //remove password
    delete user.password;
    return {
      accessToken,
      refreshToken,
      user,
    };
  }

  /** refresh access token */
  static async refreshToken(refreshToken) {
    //check if token exists
    if (!refreshToken) {
      throw new ApiError(401, "Refresh token is required");
    }
    //verify jwt
    const payload = verifyRefreshToken(refreshToken);
    //check if token exists in database
    const storedToken = await AuthModel.findRefreshToken(refreshToken);
    if (!storedToken) {
      throw new ApiError(401, "Invalid refresh token.");
    }

    const userId = payload.id;
    const user = await UserModel.findById(userId);
    if (!user) {
      throw new ApiError(404, "User not found.");
    }

    if (!user.is_active) {
      throw new ApiError(403, "Account is inactive.");
    }
    //delete old saved refresh token- for refresh token rotation
    await AuthModel.deleteRefreshToken(refreshToken);

    //genreate new tokens
    const newAccessToken = generateAccessToken(user);

    const newRefreshToken = generateRefreshToken(user);

    // Calculate expiry
    const expires_at = new Date(
      Date.now() + Number(process.env.REFRESH_TOKEN_EXPIRES_MS),
    );
    //save new refresh token
    await AuthModel.createRefreshToken(userId, newRefreshToken, expires_at);
    delete user.password;
    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      user,
    };
  }
  /**
   * Logout User
   */
  static async logout(refreshToken) {
    // Cookie already missing
    if (!refreshToken) {
      return;
    }

    // Delete refresh token if it exists
    await AuthModel.deleteRefreshToken(refreshToken);

    return;
  }
  /**
   * Logout From All Devices
   */
  static async logoutAll(userId) {
    // Ensure user exists
    const user = await UserModel.findById(userId);

    if (!user) {
      throw new ApiError(404, "User not found.");
    }

    // Revoke all refresh tokens
    await AuthModel.deleteUserRefreshTokens(userId);

    return;
  }

  /**
   * Request password reset OTP.
   *
   * Sends a one-time password to the user's registered email.
   */
  static async forgotPassword(email) {
    // Find user by email
    const user = await UserModel.findByEmail(email);

    /*
     * not reveling whether the email exists.
     */
    if (!user) {
      return;
    }

    /*
     * not sending password reset OTP to inactive accounts.
     */
    if (!user.is_active) {
      return;
    }

    /*
     * Removing any previously generated OTPs for this user.
     *
     * This ensures that only the latest OTP remains valid.
     */
    await PasswordResetOtpModel.deleteUserOtps(user.id);

    // Generate a new 6-digit OTP
    const otp = generateOtp();

    // Hash OTP before storing it in the database
    const otpHash = hashOtp(otp);

    // Calculate expiration time
    const expiresAt = getOtpExpiry();

    /*
     * Store only the hashed OTP.
     *
     * The actual OTP is sent only to the user's email.
     */
    await PasswordResetOtpModel.create({
      userId: user.id,
      otpHash,
      expiresAt,
    });

    /*
     * Send OTP to user's registered email.
     */
    await sendPasswordResetOtpEmail({
      email: user.email,
      fullName: user.full_name,
      otp,
    });
  }

  /**
   * Verify password reset OTP.
   */
  static async verifyResetOtp(email, otp) {
    // Find user
    const user = await UserModel.findByEmail(email);

    /*
     * not reveling whether the email exists.
     */
    if (!user) {
      throw new ApiError(400, "Invalid or expired OTP.");
    }

    // Get the latest valid OTP
    const resetOtp = await PasswordResetOtpModel.findLatestValidByUserId(
      user.id,
    );

    if (!resetOtp) {
      throw new ApiError(400, "Invalid or expired OTP.");
    }

    /*
     * Maximum allowed attempts.
     */
    const maxAttempts = 5;

    if (resetOtp.attempts >= maxAttempts) {
      throw new ApiError(
        429,
        "Too many incorrect OTP attempts. Please request a new OTP.",
      );
    }

    /*
     * Hash the OTP provided by the user.
     */
    const otpHash = hashOtp(otp);

    /*
     * Compare the hash stored in the database
     * with the hash of the submitted OTP.
     */
    if (otpHash !== resetOtp.otp_hash) {
      await PasswordResetOtpModel.incrementAttempts(resetOtp.id);

      throw new ApiError(400, "Invalid or expired OTP.");
    }

    /*
     * Mark OTP as verified so it cannot be reused.
     */
    await PasswordResetOtpModel.markAsVerified(resetOtp.id);

    // return {
    //   userId: user.id,
    // };
    const resetToken = generatePasswordResetToken(user.id);

    return {
      resetToken,
    };
  }

  /**
   * Reset user's password after successful OTP verification.
   *
   * @param {string} resetToken - Short-lived password reset token
   * @param {string} newPassword - New plain-text password
   */
  static async resetPassword(resetToken, newPassword) {
    if (!resetToken) {
      throw new ApiError(400, "Password reset token is required.");
    }

    if (!newPassword) {
      throw new ApiError(400, "New password is required.");
    }

    /*
     * Verify the short-lived password reset token.
     *
     * This token is generated only after successful
     * OTP verification.
     */
    const payload = verifyPasswordResetToken(resetToken);

    const userId = payload.id;

    if (!userId) {
      throw new ApiError(400, "Invalid password reset token.");
    }

    /*
     * Find the user.
     */
    const user = await UserModel.findById(userId);

    if (!user) {
      throw new ApiError(404, "User account not found.");
    }

    /*
     * not allow password reset for inactive accounts.
     */
    if (!user.is_active) {
      throw new ApiError(403, "Your account is inactive.");
    }

    /*
     * Hash the new password using the same password
     */
    const passwordHash = await hashPassword(newPassword);

    /*
     * Update the user's password.
     */
    const updatedUser = await UserModel.updatePassword(userId, passwordHash);

    if (!updatedUser) {
      throw new ApiError(500, "Failed to update password.");
    }

    /*
     * IMPORTANT:
     *
     * Password has changed, so invalidate all existing
     * refresh tokens for this user.
     *
     * This forces all existing sessions/devices to log in
     * again with the new password.
     */
    await AuthModel.deleteUserRefreshTokens(userId);

    return true;
  }
}
export default AuthService;
