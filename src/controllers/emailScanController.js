import EmailScanService from "../services/emailScanService.js";
import ApiResponse from "../utils/ApiResponse.js";
import catchAsync from "../utils/catchAsync.js";

class EmailScanController {
  /**
   * Create and scan an email.
   *
   * POST /riskradar/scan/email
   */
  static scanEmail = catchAsync(async (request, response) => {
    const { id: userId } = request.user;

    const emailData = request.body;

    const result = await EmailScanService.createAndScanEmail(userId, emailData);

    return response
      .status(200)
      .json(new ApiResponse(200, "Email scanned successfully.", result));
  });

  /**
   * Get email scan by ID.
   *
   * GET /riskradar/email-scan/:id
   */
  static getById = catchAsync(async (request, response) => {
    const { id } = request.params;

    const emailScan = await EmailScanService.getById(id);

    return response.status(200).json(
      new ApiResponse(200, "Email scan fetched successfully.", {
        emailScan,
      }),
    );
  });

  /**
   * Get email scan by parent scan ID.
   *
   * GET /riskradar/email-scan/:scanId/scan
   */
  static getByScanId = catchAsync(async (request, response) => {
    const { scanId } = request.params;

    const emailScan = await EmailScanService.getByScanId(scanId);

    return response.status(200).json(
      new ApiResponse(200, "Email scan fetched successfully.", {
        emailScan,
      }),
    );
  });

  /**
   * Update an email scan.
   *
   * PUT /riskradar/email-scans/:id
   */
  static update = catchAsync(async (request, response) => {
    const { id } = request.params;

    const updatedEmailScan = await EmailScanService.update(id, request.body);

    return response.status(200).json(
      new ApiResponse(200, "Email scan updated successfully.", {
        emailScan: updatedEmailScan,
      }),
    );
  });

  /**
   * Delete an email scan.
   *
   * DELETE /riskradar/email-scan/:id
   */
  static delete = catchAsync(async (request, response) => {
    const { id } = request.params;

    const deletedEmailScan = await EmailScanService.delete(id);

    return response.status(200).json(
      new ApiResponse(200, "Email scan deleted successfully.", {
        emailScan: deletedEmailScan,
      }),
    );
  });
}

export default EmailScanController;
