import { Router } from "express";

import AdminUserController from "../controllers/adminUserController.js";

import authMiddleware from "../middlewares/authMiddleware.js";
import authorize from "../middlewares/authorize.js";
import validateRequest from "../middlewares/validateRequest.js";

import {
  getUsersValidation,
  getUserByIdValidation,
  updateUserStatusValidation,
  updateUserRoleValidation,
  deleteUserValidation,
} from "../validations/adminUserValidation.js";

const router = Router();

/*
 * All routes in this router require:
 *
 * 1. Valid access token
 * 2. ADMIN role
 */
router.use(authMiddleware, authorize("ADMIN"));

/**
 * GET /riskradar/users/admin
 *
 * List users with:
 * - pagination
 * - search
 * - role filter
 * - active/inactive filter
 */
router.get(
  "/admin",
  getUsersValidation,
  validateRequest,
  AdminUserController.getUsers,
);

/**
 * GET /riskradar/users/:id/admin
 *
 * Get user details and scan statistics.
 */
router.get(
  "/:id",
  getUserByIdValidation,
  validateRequest,
  AdminUserController.getUserById,
);

/**
 * PATCH /riskradar/users/:id/admin/status
 *
 * Activate/deactivate user.
 *
 * Body:
 * {
 *   "isActive": false
 * }
 */
router.patch(
  "/:id/admin/status",
  updateUserStatusValidation,
  validateRequest,
  AdminUserController.updateUserStatus,
);

/**
 * PATCH /riskradar/users/:id/admin/role
 *
 * Change USER <-> ADMIN.
 *
 * Body:
 * {
 *   "role": "ADMIN"
 * }
 */
router.patch(
  "/:id/admin/role",
  updateUserRoleValidation,
  validateRequest,
  AdminUserController.updateUserRole,
);

/**
 * DELETE /riskradar/users/:id/admin
 *
 * Delete a user.
 */
router.delete(
  "/:id/admin",
  deleteUserValidation,
  validateRequest,
  AdminUserController.deleteUser,
);

export default router;
