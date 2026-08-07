import { body } from "express-validator";

const messageScanValidation = [
  body("platform")
    .optional({ values: "null" })
    .trim()
    .isIn([
      "SMS",
      "WHATSAPP",
      "TELEGRAM",
      "MESSENGER",
      "SIGNAL",
      "DISCORD",
      "SLACK",
      "FACEBOOK",
      "INSTAGRAM",
      "TWITTER",
      "LINKEDIN",
      "SNAPCHAT",
      "TIKTOK",
      "OTHER",
    ])
    .withMessage("Invalid platform."),

  body("sender")
    .optional({ values: "null" })
    .trim()
    .isLength({ max: 255 })
    .withMessage("Sender cannot exceed 255 characters."),

  body("sender_id")
    .optional({ values: "null" })
    .trim()
    .isLength({ max: 255 })
    .withMessage("Sender ID cannot exceed 255 characters."),

  body("language")
    .optional({ values: "null" })
    .trim()
    .isLength({ max: 20 })
    .withMessage("Language cannot exceed 20 characters."),

  body("message")
    .trim()
    .notEmpty()
    .withMessage("Message is required.")
    .isString()
    .withMessage("Message must be a string.")
    .isLength({ min: 2 })
    .withMessage("Message must contain at least 2 characters.")
    .isLength({ max: 10000 })
    .withMessage("Message cannot exceed 10000 characters."),
];

export default messageScanValidation;
