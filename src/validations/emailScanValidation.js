import { body } from "express-validator";

const emailScanValidation = [
  body("sender_email")
    .trim()
    .notEmpty()
    .withMessage("Sender email is required.")
    .isEmail()
    .withMessage("Please provide a valid sender email address.")
    .normalizeEmail(),

  body("reply_to")
    .optional({ values: "null" })
    .trim()
    .isEmail()
    .withMessage("Reply-to must be a valid email address.")
    .normalizeEmail(),

  body("return_path")
    .optional({ values: "null" })
    .trim()
    .isEmail()
    .withMessage("Return path must be a valid email address.")
    .normalizeEmail(),

  body("subject")
    .optional({ values: "null" })
    .isString()
    .withMessage("Subject must be a string.")
    .trim()
    .isLength({ max: 1000 })
    .withMessage("Subject cannot exceed 1000 characters."),

  body("body")
    .optional({ values: "null" })
    .isString()
    .withMessage("Email body must be a string.")
    .trim(),

  body("attachment_found")
    .optional({ values: "null" })
    .isBoolean()
    .withMessage("attachment_found must be a boolean.")
    .toBoolean(),

  body("spf_result")
    .optional({ values: "null" })
    .isString()
    .withMessage("SPF result must be a string.")
    .trim()
    .isLength({ max: 20 })
    .withMessage("SPF result cannot exceed 20 characters."),

  body("dkim_result")
    .optional({ values: "null" })
    .isString()
    .withMessage("DKIM result must be a string.")
    .trim()
    .isLength({ max: 20 })
    .withMessage("DKIM result cannot exceed 20 characters."),

  body("dmarc_result")
    .optional({ values: "null" })
    .isString()
    .withMessage("DMARC result must be a string.")
    .trim()
    .isLength({ max: 20 })
    .withMessage("DMARC result cannot exceed 20 characters."),
];

export default emailScanValidation;
