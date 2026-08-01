import { body, param, query } from "express-validator";

/**
 * Allowed scan types
 */
const scanTypes = ["URL", "EMAIL", "MESSAGE"];
/**
 * Allowed scan statuses
 */
const scanStatuses = ["PENDING", "PROCESSING", "COMPLETED", "FAILED"];

/**
 * Create scan validation
 *
 * POST /riskradar/scans
 */
export const createScanValidation = [
  body("scan_type")
    .trim()
    .notEmpty()
    .withMessage("Scan type is required.")
    .isIn(scanTypes)
    .withMessage("Scan type must be one of URL, EMAIL, or MESSAGE."),
];

/**
 * Scan ID parameter validation
 *
 * Used by:
 * GET /scans/:id
 * POST /scans/:id/start
 * POST /scans/:id/complete
 * POST /scans/:id/fail
 * DELETE /scans/:id
 */
export const scanIdValidation = [
  param("id")
    .trim()
    .notEmpty()
    .withMessage("Scan ID is required.")
    .isUUID()
    .withMessage("Invalid scan ID."),
];

/**
 * Get scan history validation
 *
 * GET /riskradar/scans
 */
export const getScansValidation = [
  query("page")
    .optional()
    .isInt({ min: 1 })
    .withMessage("Page must be a positive integer.")
    .toInt(),

  query("limit")
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage("Limit must be between 1 and 100.")
    .toInt(),

  query("search")
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage("Search cannot exceed 100 characters."),

  query("scan_type")
    .optional()
    .trim()
    .isIn(scanTypes)
    .withMessage("Scan type must be one of URL, EMAIL, or MESSAGE."),

  query("status")
    .optional()
    .trim()
    .isIn(scanStatuses)
    .withMessage(
      "Status must be one of PENDING, PROCESSING, COMPLETED, or FAILED.",
    ),

  query("risk_level_id")
    .optional()
    .trim()
    .isUUID()
    .withMessage("Invalid risk level ID."),

  query("sort_by")
    .optional()
    .trim()
    .isIn([
      "created_at",
      "started_at",
      "completed_at",
      "risk_score",
      "scan_duration_ms",
    ])
    .withMessage("Invalid sort field."),

  query("sort_order")
    .optional()
    .trim()
    .toUpperCase()
    .isIn(["ASC", "DESC"])
    .withMessage("Sort order must be ASC or DESC."),
];

/**
 * Complete scan validation
 *
 * POST /riskradar/scans/:id/complete
 *
 * Mainly for development/testing.
 * Later the scan engine will call the service directly.
 */
export const completeScanValidation = [
  ...scanIdValidation,

  body("risk_score")
    .notEmpty()
    .withMessage("Risk score is required.")
    .isInt({ min: 0, max: 100 })
    .withMessage("Risk score must be between 0 and 100.")
    .toInt(),

  body("risk_level_id")
    .notEmpty()
    .withMessage("Risk level ID is required.")
    .isUUID()
    .withMessage("Invalid risk level ID."),

  body("is_phishing")
    .notEmpty()
    .withMessage("Phishing result is required.")
    .isBoolean()
    .withMessage("is_phishing must be a boolean.")
    .toBoolean(),

  body("scan_duration_ms")
    .optional({ nullable: true })
    .isInt({ min: 0 })
    .withMessage("Scan duration must be a non-negative integer.")
    .toInt(),
];

/**
 * Empty-body validation for endpoints that only require scan ID
 *
 * Used for:
 * POST /scans/:id/start
 * POST /scans/:id/fail
 * DELETE /scans/:id
 */
export const scanActionValidation = [...scanIdValidation];
