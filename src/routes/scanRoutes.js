import { Router } from "express";
import authMiddleware from "../middlewares/authMiddleware.js";
import validateRequest from "../middlewares/validateRequest.js";
import ScanController from "../controllers/scanController.js";
import {
  completeScanValidation,
  createScanValidation,
  getScansValidation,
  scanActionValidation,
  scanIdValidation,
} from "../validations/scanValidation.js";
import emailScanValidation from "../validations/emailScanValidation.js";
import EmailScanController from "../controllers/emailScanController.js";
import messageScanValidation from "../validations/messageScanValidation.js";
import MessageScanController from "../controllers/messageScanController.js";

const router = Router();

/**
 * All scan routes require authentication.
 */
router.use(authMiddleware);
router.post("/url", ScanController.createAndScanUrl);

router.post("/:scanId/url", ScanController.scanUrl);

/**
 * Create and scan an email.
 *
 * POST /riskradar/scan/email
 */
router.post("/email", emailScanValidation, EmailScanController.scanEmail);
/**
 * Create and scan an email.
 *
 * POST /riskradar/scan/email
 */
router.post(
  "/message",
  messageScanValidation,
  MessageScanController.scanMessage,
);
/**
 * Create a new scan
 */
router.post(
  "/",
  createScanValidation,
  validateRequest,
  ScanController.createScan,
);

/**
 * Get authenticated user's scan history/Search and get user's scan history
 * GET /riskradar/scans
 */
router.get(
  "/",
  getScansValidation,
  validateRequest,
  ScanController.getUserScans,
);

/**
 * Get a specific scan
 * GET /riskradar/scans/:id
 */
router.get(
  "/:id",
  scanIdValidation,
  validateRequest,
  ScanController.getScanById,
);

/**
 * Start scan processing
 * POST /riskradar/scans/:id/start
 *
 * Development/testing endpoint.
 */
router.post(
  "/:id/start",
  scanActionValidation,
  validateRequest,
  ScanController.startScan,
);

/**
 * Complete scan
 * POST /riskradar/scans/:id/complete
 * Development/testing endpoint.
 */
router.post(
  "/:id/complete",
  completeScanValidation,
  validateRequest,
  ScanController.completeScan,
);

/**
 * Mark scan as failed
 * POST /riskradar/scans/:id/fail
 * Development/testing endpoint.
 */
router.post(
  "/:id/fail",
  scanActionValidation,
  validateRequest,
  ScanController.failedScan,
);

/**
 * Delete a scan
 * DELETE /riskradar/scans/:id
 */
router.delete(
  "/:id",
  scanActionValidation,
  validateRequest,
  ScanController.deleteScan,
);

export default router;
