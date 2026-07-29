import ThreatTypeModel from "../models/threatTypeModel.js";
import ApiError from "../utils/ApiError.js";

class ThreatTypeService {
  /**get all threat types */
  static async getAllThreatType() {
    const threat_types = await ThreatTypeModel.getAll();
    return threat_types;
  }
  /**get threat type by id */
  static async getById(id) {
    const threat_type = await ThreatTypeModel.getById(id);
    if (!threat_type) {
      throw new ApiError(404, "Threat type not found");
    }
    return threat_type;
  }
}
export default ThreatTypeService;
