import { Router } from "express";
import { keywordCategoryIdValidation } from "../validations/keywordCategoryValidation.js";
import KeywordCategoryController from "../controllers/keywordCategoryController.js";
import authMiddleware from "../middlewares/authMiddleware.js";
import authorize from "../middlewares/authorize.js";

const router = Router();
router.use(authMiddleware);
router.use(authorize("ADMIN"));
router.get("/all", KeywordCategoryController.getAllKeywordCategory);
router.get(
  "/:id",
  keywordCategoryIdValidation,
  KeywordCategoryController.getKeywordCategoryById,
);

export default router;
