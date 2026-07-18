import { Router } from "express";
import {
  loginValidation,
  registerValidation,
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

export default router;
