import DomainModel from "../models/domainModel.js";
import ApiError from "../utils/ApiError.js";
import { normailiseDomian } from "../utils/normalizeDomain.js";

class DomainService {
  /** Create Domain */
  static async createDomain(domainData, userId) {
    const {
      domain_name,
      list_type,
      threat_type,
      reason,
      source,
      confidence_score,
    } = domainData;
    //NOTE threat_type check from database is pending
    //check duplicate entry for domain
    const existingDomain = await DomainModel.findByDomainName(domain_name);
    if (existingDomain) {
      throw new ApiError(409, "Domian already exits");
    }
    //normailising domain
    const normalisedDomain = normailiseDomian(domain_name);
    // console.log(normalisedDomain);
    //create domain
    const domain = await DomainModel.create({
      domain_name: normalisedDomain,
      list_type,
      threat_type_id: threat_type,
      reason,
      source,
      confidence_score,
      created_by: userId,
    });
    return domain;
  }
  /** search all the domains */
  static async searchAllDomains(query) {
    const {
      page = 1,
      limit = 10,
      search = "",
      list_type,
      is_active,
      sort_by = "created_at",
      sort_order = "DESC",
    } = query;

    return await DomainModel.searchAndFindAll(
      Number(page),
      Number(limit),
      search,
      list_type,
      is_active === undefined ? undefined : is_active === "true",
      sort_by,
      sort_order.toUpperCase(),
    );
  }
  /**get all domains */
  static async getAllDomains() {
    return await DomainModel.getAll();
  }
  /** get domain by id */
  static async getDomainById(id) {
    const domain = await DomainModel.findById(id);
    if (!domain) {
      throw new ApiError(404, "Domain not found");
    }
    return domain;
  }
  /**update domain details */
  static async updateDomain(id, domainData, userId) {
    const existingDomain = await DomainModel.findById(id);
    if (!existingDomain) {
      throw new ApiError(404, "Domain not found");
    }
    const {
      domain_name,
      list_type,
      threat_type,
      reason,
      source,
      confidence_score,
    } = domainData;
    //check duplicate domain entry if user changed the domain name
    const normalisedDomain = normailiseDomian(domain_name);
    if (normalisedDomain !== existingDomain.domain_name) {
      const duplicate = await DomainModel.findByDomainName(domain_name);
      if (duplicate) {
        throw new ApiError(409, "Domain name already exits.");
      }
    }
    //update domain
    const updatedDomain = await DomainModel.update(id, {
      domain_name: normalisedDomain ?? existingDomain.domain_name,
      list_type: list_type ?? existingDomain.list_type,
      threat_type_id: threat_type ?? existingDomain.threat_type_id,
      reason: reason ?? existingDomain.reason,
      source: source ?? existingDomain.source,
      confidence_score: confidence_score ?? existingDomain.confidence_score,
      updated_by: userId,
    });
    return updatedDomain;
  }
  /** update domain status  */
  static async updateDomainStatus(id, is_active, userId) {
    const existingDomain = await DomainModel.findById(id);
    if (!existingDomain) {
      throw new ApiError(404, "Domain not found");
    }
    const updatedDomain = await DomainModel.updateStatus(id, is_active, userId);
    return updatedDomain;
  }
  /** delete domain  */
  static async deleteDomain(id) {
    const existingDomaina = await DomainModel.findById(id);
    if (!existingDomaina) {
      throw new ApiError(404, "Domain not found");
    }
    const deletedDomain = await DomainModel.delete(id);
    return deletedDomain;
  }
}

export default DomainService;
