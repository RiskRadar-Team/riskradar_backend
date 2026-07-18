import { Router } from "express";
import authMiddleware from "../middlewares/authMiddleware.js";
import UserController from "../controllers/userController.js";
const router = Router();

router.get("/profile", authMiddleware, UserController.getProfile);
router.put("/profile", authMiddleware, UserController.updateProfile);
router.put("/change-password", authMiddleware, UserController.changePassword);
router.delete("/delete-account", authMiddleware, UserController.deleteAccount);

export default router;
