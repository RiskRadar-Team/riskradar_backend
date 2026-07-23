import { Router } from "express";
import authMiddleware from "../middlewares/authMiddleware.js";
import authorize from "../middlewares/authorize.js";
import validateRequest from "../middlewares/validateRequest.js";
import {
  updateUrlStatusValidation,
  urlIdValidation,
  urlValidation,
} from "../validations/urlValidations.js";
import UrlController from "../controllers/urlController.js";
const router = Router();

/**All routes requird
 * Authencation and
 * ADMIN access
 */
router.use(authMiddleware);
router.use(authorize("ADMIN"));

router.post(
  "/",
  urlValidation,
  validateRequest,
  UrlController.createUrlController,
);

//search and find all urls
router.get("/", UrlController.searchAndFindAllURLs);
//get all urls
router.get("/all", UrlController.findAllURLs);
//get url by id
router.get("/:id", urlIdValidation, validateRequest, UrlController.getUrlById);

router.put(
  "/:id",
  urlIdValidation,
  urlValidation,
  validateRequest,
  UrlController.updateUrlController,
);

//update url status
router.patch(
  "/:id/status",
  urlIdValidation,
  updateUrlStatusValidation,
  validateRequest,
  UrlController.updateUrlStatus,
);

router.delete(
  "/:id",
  urlIdValidation,
  validateRequest,
  UrlController.deleteUrlController,
);

export default router;
