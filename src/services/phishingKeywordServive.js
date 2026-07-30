import PhishingKeywordModel from "../models/phishingKeywordModel.js";
import ApiError from "../utils/ApiError.js";
import KeywordCategoryModel from "../models/keywordCategoryModel.js";
class PhishingKeywordService {
  /** Normalize keyword */
  static normaliseKeyword(keyword) {
    return keyword.trim().toLowerCase();
  }
  /**create keyword */
  static async createKeyword(keywordData, userId) {
    const {
      keyword,
      category,
      severity,
      match_type,
      score,
      description,
      example,
      is_case_sensitive,
    } = keywordData;

    const normalisedKeyword = this.normaliseKeyword(keyword);
    //check for category exist or not
    if (category) {
      const existingCategory = await KeywordCategoryModel.getById(category);
      if (!existingCategory) {
        throw new ApiError(404, "Keyword category does not exist.");
      }
    }
    const existingKeyword =
      await PhishingKeywordModel.findByKeyword(normalisedKeyword);
    if (existingKeyword) {
      throw new ApiError(409, "Keyword already exists.");
    }
    const newKeyword = await PhishingKeywordModel.create({
      keyword: normalisedKeyword,
      category_id: category,
      severity,
      match_type,
      score,
      description,
      example,
      is_case_sensitive: is_case_sensitive ?? false,
      created_by: userId,
    });
    return newKeyword;
  }
  /** find keyword by it's id */
  static async getKeywordById(id) {
    const keyword = await PhishingKeywordModel.findById(id);
    if (!keyword) {
      throw new ApiError(404, "Keyword not found.");
    }
    return keyword;
  }
  /** get all the keywords */
  static async getAllKeyword() {
    const keywords = await PhishingKeywordModel.getAllKeywords();
    return keywords;
  }
  /** update keyword */
  static async updateKeyword(id, keywordData, userId) {
    const existingKeyword = await PhishingKeywordModel.findById(id);
    if (!existingKeyword) {
      throw new ApiError(404, "Keyword not found");
    }
    const {
      keyword,
      category,
      severity,
      match_type,
      score,
      description,
      example,
      is_case_sensitive,
      created_by,
    } = keywordData;
    const normalisedKeyword = this.normaliseKeyword(keyword);
    //check for category exist or not
    if (category) {
      const existingCategory = await KeywordCategoryModel.getById(category);
      if (!existingCategory) {
        throw new ApiError(404, "Keyword category does not exist.");
      }
    }
    if (keyword) {
      if (normalisedKeyword !== existingKeyword.keyword) {
        const isDuplicate =
          await PhishingKeywordModel.findByKeyword(normalisedKeyword);
        if (isDuplicate) {
          throw new ApiError(409, "Keyword already exists.");
        }
      }
    }
    const updatedKeyword = await PhishingKeywordModel.update(id, {
      keyword: normalisedKeyword,
      category_id: category ?? existingKeyword.category_id,
      serverity: severity ?? existingKeyword.serverity,
      match_type: match_type ?? existingKeyword.match_type,
      score: score ?? existingKeyword.score,
      description: description ?? existingKeyword.description,
      example: example ?? existingKeyword.example,
      is_case_sensitive: is_case_sensitive ?? existingKeyword.is_case_sensitive,
      updated_by: userId,
    });
    return updatedKeyword;
  }
  /** update keyword status */
  static async updateKeywordStatus(id, is_active, userId) {
    const existingKeyword = await PhishingKeywordModel.findById(id);
    if (!existingKeyword) {
      throw new ApiError(404, "Keyword not found.");
    }
    const updatedKeyword = await PhishingKeywordModel.updateStatus(
      id,
      is_active,
      userId,
    );
    return updatedKeyword;
  }
  /**search and get all the keywords */
  static async searchAndFindAll(query) {
    const {
      page = 1,
      limit = 10,
      search = "",
      category,
      serverity,
      match_type,
      is_active,
      sort_by = "created_by",
      sort_order = "DESC",
    } = query;
    const searchedKeywords = await PhishingKeywordModel.searchAndFindAll(
      Number(page),
      Number(limit),
      search,
      category,
      serverity,
      match_type,
      is_active == undefined ? undefined : is_active === "true",
      sort_by,
      sort_order.toUpperCase(),
    );
    return searchedKeywords;
  }
  /** delete a keyword */
  static async deleteKeyword(id) {
    const existingKeyword = await PhishingKeywordModel.findById(id);
    if (!existingKeyword) {
      throw new ApiError(404, "Keyword not found.");
    }
    const deletedKeyword = await PhishingKeywordModel.delete(id);
    return deletedKeyword;
  }
}

export default PhishingKeywordService;
