import MessageScanService from "../services/messageScanService.js";
import ApiResponse from "../utils/ApiResponse.js";
import catchAsync from "../utils/catchAsync.js";

class MessageScanController {
  /**Create and scan message
   * METHOD
   * POST /riskradar/scan/message
   */
  static scanMessage = catchAsync(async (request, response) => {
    const { id: userId } = request.user;
    const result = await MessageScanService.createAndScanMessage(
      userId,
      request.body,
    );
    return response
      .status(200)
      .json(new ApiResponse(200, "Message scanned successfully.", result));
  });
  /**
   * Get message scan by message scan ID.
   *
   * GET /riskradar/scan-message/:id
   */
  static getById = catchAsync(async (request, response) => {
    const { id } = request.params;
    const { id: userId } = request.user;
    const messageScan = await MessageScanService.getById(id, userId);

    return response.status(200).json(
      new ApiResponse(200, "Message scan fetched successfully.", {
        messageScan,
      }),
    );
  });

  /**
   * Get message scan by parent scan ID.
   *
   * GET /riskradar/scan-message/:scanId/scan
   */
  static getByScanId = catchAsync(async (request, response) => {
    const { scanId } = request.params;
    const { id: userId } = request.user;
    const messageScan = await MessageScanService.getByScanId(scanId, userId);

    return response.status(200).json(
      new ApiResponse(200, "Message scan fetched successfully.", {
        messageScan,
      }),
    );
  });

  /**
   * Update a message scan.
   *
   * PUT /riskradar/scan-message/:id
   */
  static update = catchAsync(async (request, response) => {
    const { id } = request.params;
    const { id: userId } = request.user;

    const updatedMessageScan = await MessageScanService.update(
      id,
      request.body,
      userId,
    );

    return response.status(200).json(
      new ApiResponse(200, "Message scan updated successfully.", {
        messageScan: updatedMessageScan,
      }),
    );
  });

  /**
   * Delete a message scan.
   *
   * DELETE /riskradar/scan-message/:id
   */
  static delete = catchAsync(async (request, res) => {
    const { id } = request.params;
    const { id: userId } = request.user;
    const deletedMessageScan = await MessageScanService.delete(id, userId);

    return res.status(200).json(
      new ApiResponse(200, "Message scan deleted successfully.", {
        messageScan: deletedMessageScan,
      }),
    );
  });
}

export default MessageScanController;
