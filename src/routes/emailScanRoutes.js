import express from "express";

import EmailScanController from "../controllers/emailScanController.js";
import emailScanValidation from "../validations/emailScanValidation.js";
import authMiddleware from "../middlewares/authMiddleware.js";

const router = express.Router();

/**
 * Get email scan by email scan ID.
 *
 * GET /riskradar/email-scan/:id
 */
router.get("/:id", authMiddleware, EmailScanController.getById);

/**
 * Get email scan by parent scan ID.
 *
 * GET /riskradar/email-scan/:scanId/scan
 */
router.get("/:scanId/scan", authMiddleware, EmailScanController.getByScanId);

/**
 * Update an email scan.
 *
 * PUT /riskradar/email-scan/:id
 */
router.put(
  "/:id",
  authMiddleware,
  emailScanValidation,
  EmailScanController.update,
);

/**
 * Delete an email scan.
 *
 * DELETE /riskradar/email-scan/:id
 */
router.delete("/:id", authMiddleware, EmailScanController.delete);

export default router;
