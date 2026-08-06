import ApiError from "../utils/ApiError.js";
import ScanModel from "../models/scanModel.js";
import EmailScanModel from "../models/emailScanModel.js";
import EmailScanner from "./emailScanner.js";

class EmailScanService {
  /**
   * Create a scan record and scan an email.
   *
   * Flow:
   *
   * PENDING
   *    ↓
   * PROCESSING
   *    ↓
   * EmailScanner.scan()
   *    ↓
   * COMPLETED
   *
   * If an error occurs:
   *
   * PROCESSING
   *    ↓
   * FAILED
   */
  static async createAndScanEmail(userId, emailData) {
    if (!userId) {
      throw new ApiError(400, "User id is required.");
    }

    if (!emailData || typeof emailData !== "object") {
      throw new ApiError(400, "Email data is required.");
    }

    if (!emailData.sender_email || typeof emailData.sender_email !== "string") {
      throw new ApiError(400, "Sender email is required.");
    }

    const startTime = Date.now();

    /*
     * 1. Create parent scan.
     */
    const scan = await ScanModel.create({
      user_id: userId,
      scan_type: "EMAIL",
      status: "PENDING",
    });

    try {
      /*
       * 2. Move scan to PROCESSING.
       */
      await ScanModel.updateStatus(scan.id, "PROCESSING");

      /*
       * 3. Run email scanner.
       */
      const scanResult = await EmailScanner.scan(scan.id, emailData);

      /*
       * 4. Calculate scan duration.
       */
      const scanDuration = Date.now() - startTime;

      /*
       * 5. Complete parent scan.
       */
      const completedScan = await ScanModel.complete(scan.id, {
        risk_score: scanResult.riskScore,

        risk_level_id: scanResult.riskLevel.id,

        is_phishing: scanResult.isPhishing,

        scan_duration_ms: scanDuration,
      });

      return {
        scan: completedScan,

        emailScan: scanResult.emailScan,

        findings: scanResult.findings,

        riskScore: scanResult.riskScore,

        riskLevel: scanResult.riskLevel,

        isPhishing: scanResult.isPhishing,

        recommendation: scanResult.recommendation,

        statistics: scanResult.statistics,
      };
    } catch (error) {
      /*
       * If scanning fails, mark the parent
       * scan as FAILED.
       */
      try {
        await ScanModel.markFailed(scan.id);
      } catch (failError) {
        /*
         * Do not hide the original scanning
         * error if updating FAILED also fails.
         */
        console.error("Failed to update scan status:", failError);
      }

      throw error;
    }
  }

  /**
   * Get email scan by its ID.
   */
  static async getById(id) {
    if (!id) {
      throw new ApiError(400, "Email scan id is required.");
    }

    const emailScan = await EmailScanModel.findById(id);

    if (!emailScan) {
      throw new ApiError(404, "Email scan not found.");
    }

    return emailScan;
  }

  /**
   * Get email scan by parent scan ID.
   */
  static async getByScanId(scanId) {
    if (!scanId) {
      throw new ApiError(400, "Scan id is required.");
    }

    const emailScan = await EmailScanModel.findByScanId(scanId);

    if (!emailScan) {
      throw new ApiError(404, "Email scan not found.");
    }

    return emailScan;
  }

  /**
   * Update an email scan.
   *
   * This can be useful later when we add:
   *
   * - SPF
   * - DKIM
   * - DMARC
   * - AI summary
   * - external email security APIs
   */
  static async update(id, data) {
    if (!id) {
      throw new ApiError(400, "Email scan id is required.");
    }

    if (!data || typeof data !== "object") {
      throw new ApiError(400, "Update data is required.");
    }

    const existing = await EmailScanModel.findById(id);

    if (!existing) {
      throw new ApiError(404, "Email scan not found.");
    }

    const updated = await EmailScanModel.update(id, data);

    return updated;
  }

  /**
   * Delete an email scan.
   */
  static async delete(id) {
    if (!id) {
      throw new ApiError(400, "Email scan id is required.");
    }

    const existing = await EmailScanModel.findById(id);

    if (!existing) {
      throw new ApiError(404, "Email scan not found.");
    }

    return EmailScanModel.delete(id);
  }
}

export default EmailScanService;
