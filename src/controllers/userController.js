import UserService from "../services/userService.js";
import catchAsync from "../utils/catchAsync.js";
import ApiError from "../utils/ApiError.js";
import ApiResponse from "../utils/ApiResponse.js";

class UserController {
  /**Get user profile/details for logged in user */
  static getProfile = catchAsync(async (request, response) => {
    const { id } = request.user;
    if (!id) {
      throw new ApiError(401, "Unauthorised Access! User identity required");
    }
    const user = await UserService.getProfile(id);
    return response
      .status(200)
      .json(new ApiResponse(200, "User details", user));
  });

  /**update profile- name of user */
  static updateProfile = catchAsync(async (request, response) => {
    const { id } = request.user;
    if (!id) {
      throw new ApiError(401, "Unauthorised Access! User identity required");
    }
    const { full_name } = request.body;
    const user = await UserService.updateProfile(id, full_name);
    return response
      .status(200)
      .json(new ApiResponse(200, "Profile updated successfully", user));
  });

  /**change password */
  static changePassword = catchAsync(async (request, response) => {
    const { id } = request.user;
    if (!id) {
      throw new ApiError(401, "Unauthorised Access! User identity required");
    }
    const { current_password, new_password } = request.body;
    // console.log("current", current_password);
    // console.log("new", new_password);
    const user = await UserService.changePassword(
      id,
      current_password,
      new_password,
    );
    return response
      .status(200)
      .json(new ApiResponse(200, "Password changed successfully", user));
  });
  /**Deactivate Account  */
  static deleteAccount = catchAsync(async (request, response) => {
    const { id } = request.user;
    if (!id) {
      throw new ApiError(401, "Unauthorised Access! User identity required");
    }
    const user = await UserService.deleteAccount(id);
    return response
      .status(200)
      .json(new ApiResponse(200, "Account Deleted Successfully", user));
  });
}
export default UserController;
