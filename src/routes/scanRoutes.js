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

const router = Router();

/**
 * All scan routes require authentication.
 */
router.use(authMiddleware);

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
