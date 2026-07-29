import { body, param } from "express-validator";

/**Domain Id validation */
export const riskLevelIdValidation = [
  param("id")
    .notEmpty()
    .withMessage("Risk Level ID is required")
    .isUUID()
    .withMessage("Please provide a valid risk level ID"),
];
