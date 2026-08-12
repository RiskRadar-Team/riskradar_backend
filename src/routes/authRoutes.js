import { Router } from "express";
import {
  forgotPasswordValidation,
  loginValidation,
  registerValidation,
  resetPasswordValidation,
  verifyResetOtpValidation,
} from "../validations/authValidation.js";
import validateRequest from "../middlewares/validateRequest.js";
import UserAuthController from "../controllers/userAuthController.js";
import authMiddleware from "../middlewares/authMiddleware.js";

const router = Router();
/**Public routes */

//register
router.post(
  "/register",
  registerValidation,
  validateRequest,
  UserAuthController.register,
);
// Login
router.post(
  "/login",
  loginValidation,
  validateRequest,
  UserAuthController.login,
);
//refresh access token
router.post("/refresh-token", UserAuthController.refreshToken);

/**protected Routes */
//logout
router.post("/logout", authMiddleware, UserAuthController.logout);
// logout From All Devices
router.post("/logout-all", authMiddleware, UserAuthController.logoutAll);
//forgot password releated routes

router.post(
  "/forgot-password",
  forgotPasswordValidation,
  validateRequest,
  UserAuthController.forgotPassword,
);

router.post(
  "/verify-reset-otp",
  verifyResetOtpValidation,
  validateRequest,
  UserAuthController.verifyResetOtp,
);

router.post(
  "/reset-password",
  resetPasswordValidation,
  validateRequest,
  UserAuthController.resetPassword,
);

export default router;
