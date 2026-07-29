import ThreatTypeService from "../services/threatTypeService.js";
import ApiResponse from "../utils/ApiResponse.js";
import catchAsync from "../utils/catchAsync.js";
class ThreatTypeController {
  /** get all domains */
  static getAllThreatType = catchAsync(async (request, response) => {
    const threats = await ThreatTypeService.getAllThreatType();
    return response
      .status(200)
      .json(new ApiResponse(200, "List of all the threat type", threats));
  });

  /** get domain by it's Id */
  static getThreatTypeById = catchAsync(async (request, response) => {
    const { id } = request.params;
    const threat = await ThreatTypeService.getById(id);
    return response
      .status(200)
      .json(new ApiResponse(200, "Threat type details", threat));
  });
}

export default ThreatTypeController;
