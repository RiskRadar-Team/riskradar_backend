import { Router } from "express";
import DomainController from "../controllers/domainController.js";
import authMiddleware from "../middlewares/authMiddleware.js";
import authorize from "../middlewares/authorize.js";
import {
  domainIdValidation,
  domianDetailsValidation,
  updateDomainStatusValidation,
} from "../validations/domainValidation.js";
import validateRequest from "../middlewares/validateRequest.js";
const router = Router();

/** since all the router required admin access so declaring is first */
router.use(authMiddleware);
router.use(authorize("ADMIN"));

router.post(
  "/",
  domianDetailsValidation,
  validateRequest,
  DomainController.createDomain,
);

/** route for searching and sorting */
router.get("/", DomainController.searchAllDomains);
/** to get all the domain exists in database */
router.get("/all", DomainController.getAllDomains);

router.get(
  "/:id",
  domainIdValidation,
  validateRequest,
  DomainController.getDomainById,
);

router.put(
  "/:id",
  domainIdValidation,
  domianDetailsValidation,
  validateRequest,
  DomainController.updateDomain,
);

/** since updating a single field, this is why using patch- for partial update */
router.patch(
  "/:id/status",
  domainIdValidation,
  updateDomainStatusValidation,
  validateRequest,
  DomainController.updateDomainStatus,
);
router.delete(
  "/:id",
  domainIdValidation,
  validateRequest,
  DomainController.deleteDomain,
);

export default router;
