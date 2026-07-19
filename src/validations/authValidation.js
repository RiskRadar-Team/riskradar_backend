import { body } from "express-validator";
const passwordValidator = body("password")
  .notEmpty()
  .withMessage("Password is required.")
  .isLength({ min: 8 })
  .withMessage("Password must be at least 8 characters.")
  .matches(/[A-Z]/)
  .withMessage("Password must contain at least one uppercase letter.")
  .matches(/[a-z]/)
  .withMessage("Password must contain at least one lowercase letter.")
  .matches(/[0-9]/)
  .withMessage("Password must contain at least one number.")
  .matches(/[!@#$%^&*(),.?":{}|<>]/)
  .withMessage("Password must contain at least one special character.");

export const registerValidation = [
  body("full_name")
    .trim()
    .notEmpty()
    .withMessage("Full name required")
    .isLength({ min: 3, max: 100 })
    .withMessage("Full name must be between 3 and 100 characters."),

  body("email")
    .trim()
    .notEmpty()
    .withMessage("Email required")
    .isEmail()
    .withMessage("Please provide a valid email.")
    .normalizeEmail(),
  passwordValidator,
];

export const loginValidation = [
  body("email")
    .trim()
    .notEmpty()
    .withMessage("Email is required.")
    .isEmail()
    .withMessage("Please provide a valid email.")
    .normalizeEmail(),

  body("password").notEmpty().withMessage("Password is required."),
];
export const changePasswordValidation = [
  body("current_password")
    .notEmpty()
    .withMessage("Current password is required."),
  passwordValidator,
];

export const adminDetailsValidation = [
  body("full_name")
    .trim()
    .notEmpty()
    .withMessage("Full name required")
    .isLength({ min: 3, max: 100 })
    .withMessage("Full name must be between 3 and 100 characters."),

  body("email")
    .trim()
    .notEmpty()
    .withMessage("Email is required.")
    .isEmail()
    .withMessage("Please provide a valid email.")
    .normalizeEmail(),
  passwordValidator,
];
