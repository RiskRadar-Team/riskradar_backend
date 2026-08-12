import { Router } from "express";
import authMiddleware from "../middlewares/authMiddleware.js";
import validateRequest from "../middlewares/validateRequest.js";
import {
  getScansValidation,
  getScanByIdValidation,
} from "../validations/adminScanValidation.js";
import AdminScanController from "../controllers/adminScanController.js";
import authorize from "../middlewares/authorize.js";
const router = Router();

/** since all the router required admin access so declaring is first */
router.use(authMiddleware);
router.use(authorize("ADMIN"));
/**
 * GET /riskradar/admin/scans
 *
 * Query parameters:
 *
 * ?page=1
 * ?limit=20
 * ?userId=<UUID>
 * ?scanType=URL
 * ?riskLevel=HIGH
 * ?isPhishing=true
 * ?status=COMPLETED
 * ?from=2026-08-01
 * ?to=2026-08-12
 */
router.get(
  "/",
  getScansValidation,
  validateRequest,
  AdminScanController.getScans,
);
/**
 * GET /riskradar/admin/scans/:scanId
 */

router.get(
  "/:scanId",
  getScanByIdValidation,
  validateRequest,
  AdminScanController.getScanById,
);

export default router;
