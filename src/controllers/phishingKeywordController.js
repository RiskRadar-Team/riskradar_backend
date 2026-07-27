import PhishingKeywordService from "../services/phishingKeywordServive.js";

import ApiResponse from "../utils/ApiResponse.js";
import catchAsync from "../utils/catchAsync.js";

class PhishingKeywordController {
  /**create keyword  */
  static createKeyword = catchAsync(async (request, response) => {
    const { id: userId } = request.user;
    const keywordData = request.body;
    const keyword = await PhishingKeywordService.createKeyword(
      keywordData,
      userId,
    );
    return response
      .status(201)
      .json(new ApiResponse(201, "Keyword created successfullly.", keyword));
  });
  /**get keyword by id */
  static getKeywordById = catchAsync(async (request, response) => {
    const { id } = request.params;
    const keyword = await PhishingKeywordService.getKeywordById(id);

    return response
      .status(200)
      .json(
        new ApiResponse(200, "Keyword details fetched successfully.", keyword),
      );
  });
  /** get all the keyword */
  static getAllKeyword = catchAsync(async (request, response) => {
    const keywords = await PhishingKeywordService.getAllKeyword();
    return response
      .status(200)
      .json(new ApiResponse(200, "Keywords fetched successfully.", keywords));
  });
  /**search and fetch all keywords */
  static searchAndFindAllKeywords = catchAsync(async (request, response) => {
    const searchResult = await PhishingKeywordService.searchAndFindAll(
      request.query,
    );
    return response
      .status(200)
      .json(
        new ApiResponse(200, "Keywords fetched successfully.", searchResult),
      );
  });
  /**update keyword */
  static updateKeyword = catchAsync(async (request, response) => {
    const { id } = request.params;
    const keywordData = request.body;
    const { id: userId } = request.user.id;
    const keyword = await PhishingKeywordService.updateKeyword(
      id,
      keywordData,
      userId,
    );
    return response
      .status(200)
      .json(new ApiResponse(200, "Keyword updated successfully.", keyword));
  });
  /**update keyword  status*/
  static updateKeywordStatus = catchAsync(async (request, response) => {
    const { id } = request.params;
    const { is_active } = request.body;
    const { id: userId } = request.user.id;
    const keyword = await PhishingKeywordService.updateKeywordStatus(
      id,
      is_active,
      userId,
    );
    return response
      .status(200)
      .json(
        new ApiResponse(200, "Keyword status updated successfully.", keyword),
      );
  });
  /**delete keyword */
  static deleteKeyword = catchAsync(async (request, response) => {
    const { id } = request.params;

    const keyword = await PhishingKeywordService.deleteKeyword(id);
    return response
      .status(200)
      .json(new ApiResponse(200, "Keyword deleted successfully.", keyword));
  });
}

export default PhishingKeywordController;
