import { Router } from "express";
import PhishingKeywordController from "../controllers/phishingKeywordController.js";

import authMiddleware from "../middlewares/authMiddleware.js";
import authorize from "../middlewares/authorize.js";
import validateRequest from "../middlewares/validateRequest.js";

import {
  keywordIdValidation,
  updateKeywordStatusValidation,
  keywordValidation,
} from "../validations/phishingKeywordValidation.js";

const router = Router();

router.use(authMiddleware);
router.use(authorize("ADMIN"));

router.post(
  "/",
  keywordValidation,
  validateRequest,
  PhishingKeywordController.createKeyword,
);
router.get("/all", PhishingKeywordController.getAllKeyword);
router.get(
  "/:id",
  keywordIdValidation,
  validateRequest,
  PhishingKeywordController.getKeywordById,
);
router.get("/", PhishingKeywordController.searchAndFindAllKeywords);
router.put(
  "/:id",
  keywordIdValidation,
  keywordValidation,
  validateRequest,
  PhishingKeywordController.updateKeyword,
);
router.patch(
  "/:id/status",
  keywordIdValidation,
  updateKeywordStatusValidation,
  validateRequest,
  PhishingKeywordController.updateKeywordStatus,
);

router.delete(
  "/:id",
  keywordIdValidation,
  validateRequest,
  PhishingKeywordController.deleteKeyword,
);

export default router;
