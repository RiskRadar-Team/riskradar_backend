import bcrypt from "bcrypt";
import UserModel from "../models/userModel.js";
import ApiError from "../utils/ApiError.js";
import { hashPassword, comparePassword } from "../utils/password.js";
class UserService {
  /**get user profile service */
  static async getProfile(userId) {
    const user = await UserModel.findById(userId);
    if (!user) {
      throw new ApiError(404, "User not found");
    }
    //removing sensitive field
    delete user.password;
    return user;
  }
  /**update user profile service */
  static async updateProfile(userId, full_name) {
    const user = await UserModel.findById(userId);
    if (!user) {
      throw new ApiError(404, "User not found");
    }
    const updatedUser = await UserModel.updateProfile(userId, full_name);
    if (!updatedUser) {
      throw new ApiError(500, "Could not update profile");
    }
    delete updatedUser.password;
    return updatedUser;
  }
  /**change password */
  static async changePassword(userId, current_password, new_password) {
    const user = await UserModel.findById(userId);
    if (!user) {
      throw new ApiError(404, "User not found");
    }
    const isPasswordCorrect = await comparePassword(
      current_password,
      user.password,
    );
    if (!isPasswordCorrect) {
      throw new ApiError(400, "Current password is incorrect.");
    }
    const isPasswordSame = await comparePassword(new_password, user.password);
    if (isPasswordSame) {
      throw new ApiError(400, "New password can't be same as current password");
    }
    const hashedPassword = await hashPassword(new_password);
    const updatedUser = await UserModel.changePassword(user.id, hashedPassword);
    delete updatedUser.password;
    return updatedUser;
  }
  /** delete account- soft delete only deactive the user */
  static async deleteAccount(userId) {
    const user = await UserModel.findById(userId);
    if (!user) {
      throw new ApiError(404, "User not found");
    }
    const updatedUser = await UserModel.updateStatus(userId, false);
    delete updatedUser.password;
    return updatedUser;
  }
}
export default UserService;
