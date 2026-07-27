import { body, param } from "express-validator";
import { KEYWORD_CATEGORIES } from "../constants/Constants.js";
import { MATCH_TYPES } from "../constants/Constants.js";

/**Create keyword validation */
export const keywordValidation = [
  body("keyword")
    .trim()
    .notEmpty()
    .withMessage("Keyword is required.")
    .isLength({ min: 2, max: 255 })
    .withMessage("Keyword must be between 2 and 255 characters."),
  body("category")
    .trim()
    .notEmpty()
    .withMessage("Category is required.")
    .isIn(KEYWORD_CATEGORIES)
    .withMessage("Invalid keyword category."),
  body("severity")
    .notEmpty()
    .withMessage("Severity is required.")
    .isInt({ min: 1, max: 5 })
    .withMessage("Severity must be between 1 and 5."),
  body("match_type")
    .optional()
    .trim()
    .isIn(MATCH_TYPES)
    .withMessage("Invalid match type."),

  body("score")
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage("Keyword score must be between 0 and 100."),

  body("description")
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage("Description cannot exceed 1000 characters."),
  body("example")
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage("Example cannot exceed 500 characters."),

  body("is_case_sensitive")
    .optional()
    .isBoolean()
    .withMessage("is_case_sensitive must be true or false."),
];

/**
 * Update Keyword Status Validation
 */
export const updateKeywordStatusValidation = [
  body("is_active")
    .notEmpty()
    .withMessage("is_active is required.")
    .isBoolean()
    .withMessage("is_active must be true or false."),
];

/**
 * Keyword ID Validation
 */
export const keywordIdValidation = [
  param("id")
    .notEmpty()
    .withMessage("Keyword ID is required.")
    .isUUID()
    .withMessage("Invalid Keyword ID."),
];
