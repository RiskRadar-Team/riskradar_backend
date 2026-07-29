import { Router } from "express";
import { riskLevelIdValidation } from "../validations/riskLevelValidation.js";
import RiskLevelController from "../controllers/riskLevelController.js";

const router = Router();

router.get("/all", RiskLevelController.getAllRiskLevel);
router.get("/:id", riskLevelIdValidation, RiskLevelController.getRiskLevelById);

export default router;
