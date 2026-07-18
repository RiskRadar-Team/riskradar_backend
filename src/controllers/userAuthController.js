import AuthService from "../services/authService.js";
import { createTokenCookie, destroyTokenCookie } from "../utils/cookie.js";

import ApiResponse from "../utils/ApiResponse.js";
import catchAsync from "../utils/catchAsync.js";
class UserAuthController {
  /** register user controller  */
  static register = catchAsync(async (request, response) => {
    const data = await AuthService.register(request.body);
    //create httpOnly cookie
    createTokenCookie(response, data.refreshToken);
    delete data.refreshToken;
    return response
      .status(201)
      .json(new ApiResponse(201, "Registration successful.", data));
  });
  /**login user controller */
  static login = catchAsync(async (request, response) => {
    console.log(request.body);
    const data = await AuthService.login(request.body);

    createTokenCookie(response, data.refreshToken);

    delete data.refreshToken;

    return response
      .status(200)
      .json(new ApiResponse(200, "Login successful.", data));
  });
  /**refreshToken controller */
  static refreshToken = catchAsync(async (request, response) => {
    const refreshToken = request.cookies.refreshToken;

    const data = await AuthService.refreshToken(refreshToken);

    createTokenCookie(response, data.refreshToken);

    delete data.refreshToken;

    return response
      .status(200)
      .json(new ApiResponse(200, "Access token refreshed successfully.", data));
  });
  /**logout controller */
  static logout = catchAsync(async (request, response) => {
    const refreshToken = request.cookies.refreshToken;

    await AuthService.logout(refreshToken);

    destroyTokenCookie(response);

    return response
      .status(200)
      .json(new ApiResponse(200, "Logged out successfully."));
  });

  /**
   * logout from all devices controller
   */
  static logoutAll = catchAsync(async (request, response) => {
    await AuthService.logoutAll(request.user.id);

    destroyTokenCookie(response);

    return response
      .status(200)
      .json(new ApiResponse(200, "Logged out from all devices successfully."));
  });
}
export default UserAuthController;
