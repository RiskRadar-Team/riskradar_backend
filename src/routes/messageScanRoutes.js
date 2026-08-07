import express from "express";

import MessageScanController from "../controllers/messageScanController.js";
import messageScanValidation from "../validations/messageScanValidation.js";
import authMiddleware from "../middlewares/authMiddleware.js";

const router = express.Router();

/**
 * Create and scan a message.
 *
 * POST /riskradar/scan/message
 */
// router.post(
//   "/message",
//   authMiddleware,
//   messageScanValidation,
//   MessageScanController.scanMessage,
// );

/**
 * Get message scan by message scan ID.
 *
 * GET /riskradar/scans/scan-message/:id
 */
router.get("/:id", authMiddleware, MessageScanController.getById);

/**
 * Get message scan by parent scan ID.
 *
 * GET /riskradar/scans/scan-message/scan/:scanId
 */
router.get("/:scanId/scan", authMiddleware, MessageScanController.getByScanId);

/**
 * Update a message scan.
 *
 * PUT /riskradar/scans/scan-message/:id
 */
router.put(
  "/:id",
  authMiddleware,
  messageScanValidation,
  MessageScanController.update,
);

/**
 * Delete a message scan.
 *
 * DELETE /riskradar/scans/scan-message/:id
 */
router.delete("/:id", authMiddleware, MessageScanController.delete);

export default router;
