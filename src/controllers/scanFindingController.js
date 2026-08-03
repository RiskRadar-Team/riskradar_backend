import ScanFindingService from "../services/scanFindingService.js";
import ApiResponse from "../utils/ApiResponse.js";
import catchAsync from "../utils/catchAsync.js";

class ScanFindingContoller {
  /**Create a scan finding
   * METHOD
   * POST /riskradar/scan-findings/:scanId
   */
  static createScanFinding = catchAsync(async (request, response) => {
    const { scanId } = request.params;
    const { id: userId } = request.user;
    const finding = await ScanFindingService.createFinding(
      scanId,
      request.body,
      userId,
    );
    return response
      .status(201)
      .json(
        new ApiResponse(201, "Scan finding created successfully.", finding),
      );
  });
  /**
   * get findings by its ID
   * METHOD
   * GET /riskradar/scan-findings/:id
   */
  static getFindingById = catchAsync(async (request, response) => {
    const { id } = request.params;
    const { id: userId } = request.user;
    const finding = await ScanFindingService.getFindingById(id, userId);
    return response
      .status(200)
      .json(
        new ApiResponse(200, "Scan finding fetched successfully.", finding),
      );
  });
  /**
   * Get all findings for a scan
   * METHOD
   * GET /riskradar/scan-findings/:scanId/scan
   */
  static getFindingsByScanId = catchAsync(async (request, response) => {
    const { scanId } = request.params;
    const { id: userId } = request.user;
    const findings = await ScanFindingService.getFindingsByScanId(
      scanId,
      userId,
    );
    return response
      .status(200)
      .json(
        new ApiResponse(200, "Scan findings fetched successfully.", findings),
      );
  });
  /**
   * Get findings by type
   * METHOD
   * GET
   * /riskradar/scan-findings/:scanId/scan/:findigngType/type
   */
  static getFindingsByType = catchAsync(async (request, response) => {
    const { scanId, findingType } = request.params;
    const { id: userId } = request.user;
    const findings = await ScanFindingService.getFindingsByType(
      scanId,
      findingType,
      userId,
    );
    return response.status(200).json(
      new ApiResponse(200, "Scan findings fetch successfully", {
        findings,
        count: findings.length,
        findingType,
      }),
    );
  });

  /**
   * Get high risk findings
   * METHOD
   * GET
   * /riskradar/scan-findings/:scanId/scan/high-risk
   */
  static getHighRiskFindings = catchAsync(async (request, response) => {
    const { scanId } = request.params;
    const { id: userId } = request.user;
    const findings = await ScanFindingService.getHighRiskFindings(
      scanId,
      userId,
    );
    return response.status(200).json(
      new ApiResponse(200, "High-risk findings fetch successfully", {
        findings,
        count: findings.length,
      }),
    );
  });
  /**
   * Get findings summary
   * METHOD
   * GET
   * /riskradar/scan-findings/:scanId/scan/summary
   */
  static getFindingSummary = catchAsync(async (request, response) => {
    const { scanId } = request.params;
    const { id: userId } = request.user;
    const summary = await ScanFindingService.getFindingSummary(scanId, userId);
    return response
      .status(200)
      .json(
        new ApiResponse(
          200,
          "Scan findings summary fetch successfully",
          summary,
        ),
      );
  });

  /**
   * Update a finding
   * METHOD
   * PATCH/PUT /riskradar/scan-findings/:id
   */
  static updateFinding = catchAsync(async (request, response) => {
    const { id } = request.params;
    const data = request.body;
    const { id: userId } = request.user;

    const finding = await ScanFindingService.updateFinding(id, data, userId);
    return response
      .status(200)
      .json(
        new ApiResponse(200, "Scan finding updated successfully.", finding),
      );
  });
  /**
   * delete a scan findigns
   * METHOD
   * DELETE /riskradar/scan-findings/:id
   */
  static deleteFinding = catchAsync(async (request, response) => {
    const { id } = request.params;
    const { id: userId } = request.user;
    const deletedFinding = await ScanFindingService.deleteFinding(id, userId);
    return response
      .status(200)
      .json(
        new ApiResponse(
          200,
          "Scan finding deleted successfully.",
          deletedFinding,
        ),
      );
  });
  /**
   * delete all scan finding by its scan id
   * METHOD
   * DELETE /riskradar/scan-findings/:scanId/scan
   *
   */
  static deleteFindingsByScanId = catchAsync(async (request, response) => {
    const { scanId } = request.params;
    const { id: userId } = request.user;
    const deletedFindings = await ScanFindingService.deleteFindingsByScanId(
      scanId,
      userId,
    );
    return response.status(200).json(
      new ApiResponse(200, "Scan findings deleted successfully.", {
        deletedCount: deletedFindings.length,
        findings: deletedFindings,
      }),
    );
  });
}
export default ScanFindingContoller;
