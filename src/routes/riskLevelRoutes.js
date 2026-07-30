import { Router } from "express";
import { riskLevelIdValidation } from "../validations/riskLevelValidation.js";
import RiskLevelController from "../controllers/riskLevelController.js";
import authMiddleware from "../middlewares/authMiddleware.js";
import authorize from "../middlewares/authorize.js";

const router = Router();
router.use(authMiddleware);
router.use(authorize("ADMIN"));

router.get("/all", RiskLevelController.getAllRiskLevel);
router.get("/:id", riskLevelIdValidation, RiskLevelController.getRiskLevelById);

export default router;
