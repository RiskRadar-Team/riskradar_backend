import { body, param } from "express-validator";

/**create and update domain validation */
export const domianDetailsValidation = [
  body("domain_name")
    .trim()
    .notEmpty()
    .withMessage("Domain name is required")
    .isLength({ max: 255 })
    .withMessage("Domain name cannot exeecd 255 characters")
    .isFQDN()
    .withMessage("Please provide a valid domain name."),

  body("list_type")
    .trim()
    .notEmpty()
    .withMessage("List type is required")
    .isIn(["BLACKLIST", "WHITELIST"])
    .withMessage("List type must be either BLACKLIST or WHITELIST"),

  body("threat_type")
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage("Threat type cannot exceed 100 characters"),

  body("reason")
    .optional()
    .trim()
    .isLength({ max: 600 })
    .withMessage("Reason cannot exceed 600 characters."),

  body("source")
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage("Source cannot exceed 100 characters"),

  body("confidence_score")
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage("Confidence score must be between 0 to 100."),
];

/** Domain status validation */
export const updateDomainStatusValidation = [
  body("is_active")
    .notEmpty()
    .withMessage("is_active is required")
    .isBoolean()
    .withMessage("is_active must be either true or false."),
];

/**Domain Id validation */
export const domainIdValidation = [
  param("id")
    .notEmpty()
    .withMessage("Domain ID is required")
    .isUUID()
    .withMessage("Please provide a valid domain ID"),
];
