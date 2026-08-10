import { param, query, body } from "express-validator";

/**
 * UUID validation.
 */
const userIdParam = param("id")
  .trim()
  .isUUID()
  .withMessage("User id must be a valid UUID.");

/**
 * GET /riskradar/users/admin
 *
 * Query validation:
 * ?page=1
 * ?limit=10
 * ?search=sandeep
 * ?role=USER
 * ?isActive=true
 */
export const getUsersValidation = [
  query("page")
    .optional()
    .isInt({ min: 1 })
    .withMessage("Page must be a positive integer."),

  query("limit")
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage("Limit must be between 1 and 100."),

  query("search")
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage("Search cannot exceed 100 characters."),

  query("role")
    .optional()
    .trim()
    .toUpperCase()
    .isIn(["USER", "ADMIN"])
    .withMessage("Role must be USER or ADMIN."),

  query("isActive")
    .optional()
    .trim()
    .isIn(["true", "false"])
    .withMessage("isActive must be true or false."),
];

/**
 * GET /riskradar/users/:id/admin
 */
export const getUserByIdValidation = [userIdParam];

/**
 * PATCH /riskradar/users/:id/admin/status
 *
 */
export const updateUserStatusValidation = [
  userIdParam,

  body("isActive")
    .exists()
    .withMessage("isActive is required.")
    .isBoolean()
    .withMessage("isActive must be a boolean."),
];

/**
 * PATCH /riskradar/users/:id/admin/role
 *
 */
export const updateUserRoleValidation = [
  userIdParam,

  body("role")
    .exists()
    .withMessage("Role is required.")
    .trim()
    .toUpperCase()
    .isIn(["USER", "ADMIN"])
    .withMessage("Role must be USER or ADMIN."),
];

/**
 * DELETE /riskradar/users/:id/admin
 */
export const deleteUserValidation = [userIdParam];
