import UrlService from "../services/urlService.js";
import ApiResponse from "../utils/ApiResponse.js";
import catchAsync from "../utils/catchAsync.js";

class UrlController {
  /**create url */
  static createUrlController = catchAsync(async (request, response) => {
    const urlData = request.body;
    const { id: userId } = request.user;
    const url = await UrlService.createUrl(urlData, userId);
    return response
      .status(201)
      .json(new ApiResponse(201, "Url created successfully", url));
  });
  /**search and find all urls */
  static searchAndFindAllURLs = catchAsync(async (request, response) => {
    const searchResult = await UrlService.serachAndFindAllUrls(request.query);
    return response
      .status(200)
      .json(new ApiResponse(200, "URLs fetched successfully.", searchResult));
  });
  /**find all urls */
  static findAllURLs = catchAsync(async (request, response) => {
    const urls = await UrlService.getAllUrls();
    return response
      .status(200)
      .json(new ApiResponse(200, "URLs fetched successfully.", urls));
  });
  /** find url by it's ID */
  static getUrlById = catchAsync(async (request, response) => {
    const { id } = request.params;
    const url = await UrlService.getUrlById(id);
    return response
      .status(200)
      .json(new ApiResponse(200, "URL fetched successfully.", url));
  });
  /** update url*/
  static updateUrlController = catchAsync(async (request, response) => {
    const { id } = request.params;
    const { id: userId } = request.user;
    const urlData = request.body;
    const url = await UrlService.updateUrl(id, urlData, userId);
    return response
      .status(200)
      .json(new ApiResponse(200, "URL updated successfully.", url));
  });
  /** update url status*/
  static updateUrlStatus = catchAsync(async (request, response) => {
    const { id } = request.params;
    const { id: userId } = request.user;
    const { is_active } = request.body;
    const url = await UrlService.updateUrlStatus(id, is_active, userId);
    return response
      .status(200)
      .json(new ApiResponse(200, "URL updated successfully.", url));
  });
  /** delete url*/
  static deleteUrlController = catchAsync(async (request, response) => {
    const { id } = request.params;

    const url = await UrlService.deleteUrl(id);
    return response
      .status(200)
      .json(new ApiResponse(200, "URL deleted successfully.", url));
  });
}

export default UrlController;
