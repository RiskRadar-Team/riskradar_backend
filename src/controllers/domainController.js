import DomainService from "../services/domainService.js";
import ApiResponse from "../utils/ApiResponse.js";
import catchAsync from "../utils/catchAsync.js";
class DomainController {
  /** create domain */
  static createDomain = catchAsync(async (request, response) => {
    const { id } = request.user;
    const domain = await DomainService.createDomain(request.body, id);
    return response
      .status(201)
      .json(new ApiResponse(201, "Domain created successfully", domain));
  });

  /**search domains */
  static searchAllDomains = catchAsync(async (request, response) => {
    const domains = await DomainService.searchAllDomains(request.query);

    return response
      .status(200)
      .json(new ApiResponse(200, "Domains fetched successfully.", domains));
  });
  /** get all domains */
  static getAllDomains = catchAsync(async (request, response) => {
    const domains = await DomainService.getAllDomains();
    return response
      .status(200)
      .json(new ApiResponse(200, "List of all the domains", domains));
  });

  /** get domain by it's Id */
  static getDomainById = catchAsync(async (request, response) => {
    const { id } = request.params;
    const domain = await DomainService.getDomainById(id);
    return response
      .status(200)
      .json(new ApiResponse(200, "Domain details", domain));
  });
  /**update domain  */
  static updateDomain = catchAsync(async (request, response) => {
    const { id } = request.params;
    const { id: userId } = request.user;
    const domain = await DomainService.updateDomain(id, request.body, userId);
    return response
      .status(200)
      .json(new ApiResponse(200, "Domain updated successfully", domain));
  });
  /**update domain status */
  static updateDomainStatus = catchAsync(async (request, response) => {
    const { id } = request.params;
    const { id: userId } = request.user;
    const { is_active } = request.body;
    const domain = await DomainService.updateDomainStatus(
      id,
      is_active,
      userId,
    );
    return response
      .status(200)
      .json(new ApiResponse(200, "Domain status updated successfully", domain));
  });

  /**Delete Domain */
  static deleteDomain = catchAsync(async (request, response) => {
    const { id } = request.params;
    const domain = await DomainService.deleteDomain(id);
    return response
      .status(200)
      .json(new ApiResponse(200, "Domain deleted successfully", domain));
  });
}

export default DomainController;
