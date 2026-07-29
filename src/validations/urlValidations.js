import { body, param } from "express-validator";

/**
 * Create URL Validation
 */
export const urlValidation = [
  body("url")
    .trim()
    .notEmpty()
    .withMessage("URL is required.")
    .isURL({
      protocols: ["http", "https"],
      require_protocol: true,
    })
    .withMessage("Please provide a valid URL."),

  body("list_type")
    .trim()
    .notEmpty()
    .withMessage("List type is required.")
    .isIn(["BLACKLIST", "WHITELIST"])
    .withMessage("List type must be either BLACKLIST or WHITELIST."),

  body("threat_type")
    .optional({ nullable: true })
    .isUUID()
    .withMessage("Invalid threat type."),

  body("reason")
    .optional()
    .trim()
    .isLength({ max: 600 })
    .withMessage("Reason cannot exceed 600 characters."),

  body("source")
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage("Source cannot exceed 100 characters."),

  body("confidence_score")
    .optional({ nullable: true })
    .isInt({ min: 0, max: 100 })
    .withMessage("Confidence score must be between 0 and 100."),
];

/**
 * Update URL Status Validation
 */
export const updateUrlStatusValidation = [
  body("is_active")
    .notEmpty()
    .withMessage("is_active is required.")
    .isBoolean()
    .withMessage("is_active must be true or false."),
];

/**
 * URL ID Validation
 */
export const urlIdValidation = [
  param("id")
    .notEmpty()
    .withMessage("URL ID is required.")
    .isUUID()
    .withMessage("Invalid URL ID."),
];
