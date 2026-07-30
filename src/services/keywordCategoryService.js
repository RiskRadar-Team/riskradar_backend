import KeywordCategoryModel from "../models/keywordCategoryModel.js";
import ApiError from "../utils/ApiError.js";

class KeywordCategoryService {
  /**get all keyword categories */
  static async getAllKeywordCategory() {
    const categories = await KeywordCategoryModel.getAll();
    return categories;
  }
  /**get keyword category by id */
  static async getById(id) {
    const category = await KeywordCategoryModel.getById(id);
    if (!category) {
      throw new ApiError(404, "Keyword category not found");
    }
    return category;
  }
}
export default KeywordCategoryService;
