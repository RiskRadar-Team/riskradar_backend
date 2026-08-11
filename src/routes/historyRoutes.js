import { Router } from "express";
import authMiddleware from "../middlewares/authMiddleware.js";
import validateRequest from "../middlewares/validateRequest.js";
import {
  getHistoryValidation,
  getScanByIdValidation,
} from "../validations/historyValidation.js";
import HistoryController from "../controllers/historyController.js";
const router = Router();

router.use(authMiddleware);
/**
 * GET /riskradar/history
 *
 * Query parameters:
 *
 * ?page=1
 * ?limit=20
 * ?scanType=URL
 * ?riskLevel=HIGH
 * ?isPhishing=true
 * ?from=2026-08-01
 * ?to=2026-08-11
 */
router.get(
  "/",
  getHistoryValidation,
  validateRequest,
  HistoryController.getHistory,
);
/**
 * GET /riskradar/history/:scanId
 */

router.get(
  "/:scanId",
  getScanByIdValidation,
  validateRequest,
  HistoryController.getScanById,
);

export default router;
