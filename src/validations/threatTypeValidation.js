import { body, param } from "express-validator";

/**Domain Id validation */
export const threatTypeIdValidation = [
  param("id")
    .notEmpty()
    .withMessage("Threat type ID is required")
    .isUUID()
    .withMessage("Please provide a valid threat type ID"),
];
