import { body, param } from "express-validator";

/**Domain Id validation */
export const keywordCategoryIdValidation = [
  param("id")
    .notEmpty()
    .withMessage("Keyword category ID is required")
    .isUUID()
    .withMessage("Please provide a valid keyword category ID"),
];
