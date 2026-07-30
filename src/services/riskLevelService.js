import RiskLevelModel from "../models/riskLevelModel.js";
import ApiError from "../utils/ApiError.js";

class RiskLevelService {
  /**get all risk levels */
  static async getAllRiskLevel() {
    const risks = await RiskLevelModel.getAll();
    return risks;
  }
  /**get risk level by id */
  static async getById(id) {
    const risk_level = await RiskLevelModel.getById(id);
    if (!risk_level) {
      throw new ApiError(404, "Risk level not found");
    }
    return risk_level;
  }
}
export default RiskLevelService;
