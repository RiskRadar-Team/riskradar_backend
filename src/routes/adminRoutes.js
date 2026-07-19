import { Router } from "express";
import authMiddleware from "../middlewares/authMiddleware.js";
import authorize from "../middlewares/authorize.js";
import { adminDetailsValidation } from "../validations/authValidation.js";
import validateRequest from "../middlewares/validateRequest.js";
import AdminContoller from "../controllers/adminController.js";

const router = Router();

router.post(
  "/create",
  authMiddleware,
  authorize("ADMIN"),
  adminDetailsValidation,
  validateRequest,
  AdminContoller.createAdminController,
);

export default router;
