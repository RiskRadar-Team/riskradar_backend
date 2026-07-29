import { Router } from "express";
import { threatTypeIdValidation } from "../validations/threatTypeValidation.js";
import ThreatTypeController from "../controllers/threatTypeController.js";

const router = Router();

router.get("/all", ThreatTypeController.getAllThreatType);
router.get(
  "/:id",
  threatTypeIdValidation,
  ThreatTypeController.getThreatTypeById,
);

export default router;
