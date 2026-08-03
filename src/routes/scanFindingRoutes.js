import { Router } from "express";
import authMiddleware from "../middlewares/authMiddleware.js";
import {
  createFindingValidation,
  findingIdValidation,
  findingTypeValidation,
  scanIdValidation,
  updateFindingValidation,
} from "../validations/scanFindingsValidation.js";
import validateRequest from "../middlewares/validateRequest.js";
import ScanFindingContoller from "../controllers/scanFindingController.js";
const router = Router();

/**Protecting all scan finding routes */

router.use(authMiddleware);

router.post(
  "/:scanId",
  createFindingValidation,
  validateRequest,
  ScanFindingContoller.createScanFinding,
);

router.get(
  "/:id",
  findingIdValidation,
  validateRequest,
  ScanFindingContoller.getFindingById,
);

router.get(
  "/:scanId/scan",
  scanIdValidation,
  validateRequest,
  ScanFindingContoller.getFindingsByScanId,
);

router.get(
  "/:scanId/scan/:findingType/type",
  findingTypeValidation,
  validateRequest,
  ScanFindingContoller.getFindingsByType,
);

router.get(
  "/:scanId/scan/high-risk",
  scanIdValidation,
  validateRequest,
  ScanFindingContoller.getHighRiskFindings,
);

router.get(
  "/:scanId/scan/summary",
  scanIdValidation,
  validateRequest,
  ScanFindingContoller.getFindingSummary,
);

router.put(
  "/:id",
  updateFindingValidation,
  validateRequest,
  ScanFindingContoller.updateFinding,
);

router.delete(
  "/:id",
  findingIdValidation,
  validateRequest,
  ScanFindingContoller.deleteFinding,
);

router.delete(
  "/:scanId/scan",
  scanIdValidation,
  validateRequest,
  ScanFindingContoller.deleteFindingsByScanId,
);

export default router;
