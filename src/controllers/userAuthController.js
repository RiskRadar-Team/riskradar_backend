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
    // console.log(request.body);
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
  /**
   * Request password reset OTP.
   */
  static forgotPassword = catchAsync(async (request, response) => {
    const { email } = request.body;

    await AuthService.forgotPassword(email);

    /*
     * Always return the same response whether the email
     * exists or not. This prevents email enumeration.
     */
    return response
      .status(200)
      .json(
        new ApiResponse(
          200,
          "If an account exists with this email, a password reset OTP has been sent.",
          null,
        ),
      );
  });

  /**
   * Verify password reset OTP.
   */
  static verifyResetOtp = catchAsync(async (request, response) => {
    const { email, otp } = request.body;

    const result = await AuthService.verifyResetOtp(email, otp);

    return response
      .status(200)
      .json(new ApiResponse(200, "OTP verified successfully.", result));
  });

  /**
   * Reset password.
   */
  static resetPassword = catchAsync(async (request, response) => {
    const { resetToken, password } = request.body;

    await AuthService.resetPassword(resetToken, password);

    return response
      .status(200)
      .json(
        new ApiResponse(
          200,
          "Password reset successful. You can now login with your new password.",
          null,
        ),
      );
  });
}
export default UserAuthController;
