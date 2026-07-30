import { Router } from "express";
import { threatTypeIdValidation } from "../validations/threatTypeValidation.js";
import ThreatTypeController from "../controllers/threatTypeController.js";
import authMiddleware from "../middlewares/authMiddleware.js";
import authorize from "../middlewares/authorize.js";

const router = Router();
router.use(authMiddleware);
router.use(authorize("ADMIN"));
router.get("/all", ThreatTypeController.getAllThreatType);
router.get(
  "/:id",
  threatTypeIdValidation,
  ThreatTypeController.getThreatTypeById,
);

export default router;
