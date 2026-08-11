import { param, query } from "express-validator";

/**
 * GET /riskradar/history
 *
 * Query parameters:
 *
 * ?page=1
 * ?limit=20
 * ?scanType=URL
 * ?riskLevel=HIGH
 * ?isPhishing=true
 * ?from=2026-08-01
 * ?to=2026-08-11
 */
export const getHistoryValidation = [
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
   *
   * Query parameters are strings.
   */
  query("isPhishing")
    .optional()
    .trim()
    .isIn(["true", "false"])
    .withMessage("isPhishing must be true or false."),

  /*
   * Start date.
   *
   * Accept:
   * YYYY-MM-DD
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
 * GET /riskradar/history/:scanId
 */
export const getScanByIdValidation = [
  param("scanId").trim().isUUID().withMessage("scanId must be a valid UUID."),
];

export default {
  getHistoryValidation,
  getScanByIdValidation,
};
