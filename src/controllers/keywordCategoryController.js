import KeywordCategoryService from "../services/keywordCategoryService.js";
import ApiResponse from "../utils/ApiResponse.js";
import catchAsync from "../utils/catchAsync.js";
class KeywordCategoryController {
  /** get all keyword category */
  static getAllKeywordCategory = catchAsync(async (request, response) => {
    const keywords = await KeywordCategoryService.getAllKeywordCategory();
    return response
      .status(200)
      .json(
        new ApiResponse(200, "List of all the keyword categories", keywords),
      );
  });

  /** get keyword category by it's Id */
  static getKeywordCategoryById = catchAsync(async (request, response) => {
    const { id } = request.params;
    const risk = await KeywordCategoryService.getById(id);
    return response
      .status(200)
      .json(new ApiResponse(200, "Keyword category details", risk));
  });
}

export default KeywordCategoryController;
