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
}
export default AuthService;
