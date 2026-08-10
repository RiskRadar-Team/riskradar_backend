import { Router } from "express";

import DashboardController from "../controllers/dashboardController.js";
import authMiddleware from "../middlewares/authMiddleware.js";

const router = Router();

/**
 * Get authenticated user's dashboard.
 *
 * GET /riskradar/dashboard
 *
 * Optional:
 * GET /riskradar/dashboard?period=7d
 * GET /riskradar/dashboard?period=30d
 * GET /riskradar/dashboard?period=90d
 * GET /riskradar/dashboard?period=all
 */
router.get("/", authMiddleware, DashboardController.getDashboard);

export default router;
