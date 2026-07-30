import RiskLevelService from "../services/riskLevelService.js";
import ApiResponse from "../utils/ApiResponse.js";
import catchAsync from "../utils/catchAsync.js";
class RiskLevelContoller {
  /** get all risk level  */
  static getAllRiskLevel = catchAsync(async (request, response) => {
    const risks = await RiskLevelService.getAllRiskLevel();
    return response
      .status(200)
      .json(new ApiResponse(200, "List of all the risk level", risks));
  });

  /** get risk level by it's Id */
  static getRiskLevelById = catchAsync(async (request, response) => {
    const { id } = request.params;
    const risk = await RiskLevelService.getById(id);
    return response
      .status(200)
      .json(new ApiResponse(200, "Risk level details", risk));
  });
}

export default RiskLevelContoller;
