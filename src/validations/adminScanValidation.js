import { query, param } from "express-validator";

/**
 * GET /riskradar/admin/scans
 *
 * Query parameters:
 *
 * ?page=1
 * ?limit=20
 * ?userId=<UUID>
 * ?scanType=URL
 * ?riskLevel=HIGH
 * ?isPhishing=true
 * ?status=COMPLETED
 * ?from=2026-08-01
 * ?to=2026-08-12
 */
export const getScansValidation = [
  /*
   * Pagination.
   */
  query("page")
    .optional()
    .isInt({ min: 1 })
    .withMessage("Page must be a positive integer."),

  query("limit")
    .optional()
    .isInt({
      min: 1,
      max: 100,
    })
    .withMessage("Limit must be between 1 and 100."),

  /*
   * Filter by user.
   */
  query("userId")
    .optional()
    .trim()
    .isUUID()
    .withMessage("userId must be a valid UUID."),

  /*
   * Scan type.
   */
  query("scanType")
    .optional()
    .trim()
    .toUpperCase()
    .isIn(["URL", "EMAIL", "MESSAGE"])
    .withMessage("Scan type must be URL, EMAIL, or MESSAGE."),

  /*
   * Risk level.
   */
  query("riskLevel")
    .optional()
    .trim()
    .toUpperCase()
    .isIn(["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    .withMessage("Risk level must be SAFE, LOW, MEDIUM, HIGH, or CRITICAL."),

  /*
   * Phishing filter.
   */
  query("isPhishing")
    .optional()
    .trim()
    .isIn(["true", "false"])
    .withMessage("isPhishing must be true or false."),

  /*
   * Scan status.
   *
   * Must match the scans table CHECK constraint.
   */
  query("status")
    .optional()
    .trim()
    .toUpperCase()
    .isIn(["PENDING", "PROCESSING", "COMPLETED", "FAILED"])
    .withMessage("Status must be PENDING, PROCESSING, COMPLETED, or FAILED."),

  /*
   * Start date.
   */
  query("from")
    .optional()
    .trim()
    .matches(/^\d{4}-\d{2}-\d{2}$/)
    .withMessage("from must be in YYYY-MM-DD format."),

  /*
   * End date.
   */
  query("to")
    .optional()
    .trim()
    .matches(/^\d{4}-\d{2}-\d{2}$/)
    .withMessage("to must be in YYYY-MM-DD format."),
];

/**
 * GET /riskradar/admin/scans/:scanId
 */
export const getScanByIdValidation = [
  param("scanId").trim().isUUID().withMessage("scanId must be a valid UUID."),
];

export default {
  getScansValidation,
  getScanByIdValidation,
};
