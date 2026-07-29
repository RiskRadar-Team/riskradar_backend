import UrlModel from "../models/urlModel.js";
import DomainModel from "../models/domainModel.js";

import ApiError from "../utils/ApiError.js";
import { dbPool } from "../config/db.js";
import { normailiseDomian } from "../utils/normalizeDomain.js";

class UrlService {
  /**normalise url */
  static normaliseUrl(url) {
    try {
      return new URL(url.trim()).toString();
    } catch (error) {
      throw new ApiError(400, "Invalid url.");
    }
  }
  /**create url */
  static async createUrl(urlData, userId) {
    const { url, list_type, threat_type, reason, source, confidence_score } =
      urlData;
    const normailsedUrl = this.normaliseUrl(url);
    //check duplicate url
    const existingUrl = await UrlModel.findByUrl(normailsedUrl);
    if (existingUrl) {
      throw new ApiError(409, "This URL already exists.");
    }
    //get the domian name from the url
    const domain_name = new URL(normailsedUrl).hostname;
    //find domain by name
    const normalisedDomainName = normailiseDomian(domain_name);
    const domain = await DomainModel.findByDomainName(normalisedDomainName);
    if (!domain) {
      throw new ApiError(
        404,
        `Domain not found.Tried to create new domain entry with ${normalisedDomainName}`,
      );
    }
    const domain_id = domain.id;
    const newUrl = await UrlModel.create({
      url: normailsedUrl,
      domain_id,
      list_type,
      threat_type_id: threat_type,
      reason,
      source,
      confidence_score,
      created_by: userId,
    });
    return newUrl;
  }
  /**search and get all urls */
  static async serachAndFindAllUrls(query) {
    const {
      page = 1,
      limit = 10,
      search = "",
      list_type,
      is_active,
      domain_id,
      sort_by = "created_at",
      sort_order = "DESC",
    } = query;
    const urls = await UrlModel.searchAndFindAll(
      page,
      limit,
      search,
      list_type,
      is_active === undefined ? undefined : is_active === "true",
      domain_id,
      sort_by,
      sort_order.toUpperCase(),
    );
    return urls;
  }
  /**get all urls */
  static async getAllUrls() {
    const urls = UrlModel.getAllUrls();
    return urls;
  }
  /** get url by it's ID */
  static async getUrlById(id) {
    const url = await UrlModel.findById(id);
    if (!url) {
      throw new ApiError(404, "Url not found.");
    }
    return url;
  }
  /**update url details */
  static async updateUrl(id, urlData, userId) {
    const isUrlExist = await UrlModel.findById(id);
    if (!isUrlExist) {
      throw new ApiError(404, "URL not found");
    }
    const { url, list_type, threat_type, reason, source, confidence_score } =
      urlData;
    const normalisedUrlName = this.normaliseUrl(url);
    if (normalisedUrlName !== isUrlExist.url) {
      //check for duplicate entry
      const duplicateUrl = await UrlModel.findByUrl(normalisedUrlName);
      if (duplicateUrl) {
        throw new ApiError(409, "URL already exists.");
      }
    }
    //get the domian name from the url
    const domain_name = new URL(normalisedUrlName).hostname;
    //find domain by name
    const normalisedDomainName = normailiseDomian(domain_name);
    const domain = await DomainModel.findByDomainName(normalisedDomainName);
    if (!domain) {
      throw new ApiError(
        404,
        `Domain not found.Tried to create new domain entry with ${normalisedDomainName}`,
      );
    }
    const domain_id = domain.id;
    const updatedUrl = await UrlModel.update(id, {
      url: normalisedUrlName,
      domain_id,
      list_type: list_type ?? isUrlExist.list_type,
      threat_type_id: threat_type ?? isUrlExist.threat_type_id,
      reason: reason ?? isUrlExist.reason,
      source: source ?? isUrlExist.source,
      confidence_score: confidence_score ?? isUrlExist.confidence_score,
      updated_by: userId,
    });
    return updatedUrl;
  }

  /**Update URL status */
  static async updateUrlStatus(id, is_active, userId) {
    const isUrlExist = await UrlModel.findById(id);
    if (!isUrlExist) {
      throw new ApiError(404, "URL not found");
    }
    const updatedUrl = await UrlModel.updateUrlStatus(id, is_active, userId);
    return updatedUrl;
  }
  /**Delete url */
  static async deleteUrl(id) {
    const isUrlExist = await UrlModel.findById(id);
    if (!isUrlExist) {
      throw new ApiError(404, "URL not found");
    }
    const deletedUrl = await UrlModel.delete(id);
    return deletedUrl;
  }
}
export default UrlService;
