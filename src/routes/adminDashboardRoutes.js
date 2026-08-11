import express from "express";

import AdminDashboardController from "../controllers/adminDashboardController.js";

import authMiddleware from "../middlewares/authMiddleware.js";
import authorize from "../middlewares/authorize.js";

const router = express.Router();

/*
 * All admin dashboard routes require:
 *
 * 1. Valid access token
 * 2. ADMIN role
 */
router.use(authMiddleware, authorize("ADMIN"));

/**
 * GET /riskradar/admin/dashboard
 *
 * Optional query:
 *
 * ?period=7d
 * ?period=30d
 * ?period=90d
 * ?period=all
 */
router.get("/", AdminDashboardController.getDashboard);

export default router;
