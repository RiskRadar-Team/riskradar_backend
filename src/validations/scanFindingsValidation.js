import { body, param } from "express-validator";

/**
 * Allowed finding types
 */
const FINDING_TYPES = [
  "DOMAIN",
  "URL",
  "KEYWORD",
  "HEADER",
  "LINK",
  "AI",
  "REPUTATION",
  "OTHER",
];

/**
 * Create scan finding validation
 */
export const createFindingValidation = [
  param("scanId").isUUID().withMessage("Valid scan ID is required."),

  body("finding_type")
    .trim()
    .notEmpty()
    .withMessage("Finding type is required.")
    .isIn(FINDING_TYPES)
    .withMessage(`Finding type must be one of: ${FINDING_TYPES}.`),

  body("finding_value")
    .trim()
    .notEmpty()
    .withMessage("Finding value is required.")
    .isLength({ max: 5000 })
    .withMessage("Finding value cannot exceed 5000 characters."),

  body("severity")
    .optional()
    .isInt({ min: 1, max: 5 })
    .withMessage("Severity must be an integer between 1 and 5."),

  body("score")
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage("Score must be an integer between 0 and 100."),

  body("description")
    .optional({ nullable: true })
    .trim()
    .isLength({ max: 5000 })
    .withMessage("Description cannot exceed 5000 characters."),

  body("source")
    .optional({ nullable: true })
    .trim()
    .isLength({ max: 50 })
    .withMessage("Source cannot exceed 50 characters."),

  body("evidence")
    .optional({ nullable: true })
    .isObject()
    .withMessage("Evidence must be a valid JSON object."),
];

export const findingIdValidation = [
  param("id").isUUID().withMessage("Valid finding ID is required."),
];

export const scanIdValidation = [
  param("scanId").isUUID().withMessage("Valid scan ID is required."),
];

export const findingTypeValidation = [
  param("scanId").isUUID().withMessage("Valid scan ID is required."),

  param("findingType")
    .trim()
    .notEmpty()
    .withMessage("Finding type is required.")
    .isIn(FINDING_TYPES)
    .withMessage(`Finding type must be one of: ${FINDING_TYPES.join(", ")}.`),
];

export const updateFindingValidation = [
  param("id").isUUID().withMessage("Valid finding ID is required."),

  body("finding_type")
    .optional()
    .trim()
    .isIn(FINDING_TYPES)
    .withMessage(`Finding type must be one of: ${FINDING_TYPES.join(", ")}.`),

  body("finding_value")
    .optional()
    .trim()
    .notEmpty()
    .withMessage("Finding value cannot be empty.")
    .isLength({ max: 5000 })
    .withMessage("Finding value cannot exceed 5000 characters."),

  body("severity")
    .optional()
    .isInt({ min: 1, max: 5 })
    .withMessage("Severity must be an integer between 1 and 5."),

  body("score")
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage("Score must be an integer between 0 and 100."),

  body("description")
    .optional({ nullable: true })
    .trim()
    .isLength({ max: 5000 })
    .withMessage("Description cannot exceed 5000 characters."),

  body("source")
    .optional({ nullable: true })
    .trim()
    .isLength({ max: 50 })
    .withMessage("Source cannot exceed 50 characters."),

  body("evidence")
    .optional({ nullable: true })
    .isObject()
    .withMessage("Evidence must be a valid JSON object."),
];
