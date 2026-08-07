import MessageScanModel from "../models/messageScanModel.js";
import RiskLevelModel from "../models/riskLevelModel.js";
import ScanModel from "../models/scanModel.js";

import MessageScanner from "./messageScanner.js";
import ApiError from "../utils/ApiError.js";

class MessageScanService {
  /**Create a new message scan and perform scanning */
  static async createAndScanMessage(userId, messageData) {
    const startTime = Date.now();
    /**create parent scan */
    const scan = await ScanModel.create({
      user_id: userId,
      scan_type: "MESSAGE",
      status: "PENDING",
      engine_version: "1.0.0",
    });
    /** move the scan to processing */
    await ScanModel.updateStatus(scan.id, "PROCESSING");
    try {
      /**perform scan */
      const scanResult = await MessageScanner.scan(scan.id, messageData);

      /***calculate scan duration */
      const scanDuration = Date.now() - startTime;
      /**Resolve the risk_level id */
      const riskLevel = await RiskLevelModel.getByScore(scanResult.riskScore);
      if (!riskLevel) {
        throw new ApiError(500, "Unable to determaine risk level.");
      }
      /**mark the scan complete and save the data */
      await ScanModel.complete(scan.id, {
        risk_score: scanResult.riskScore,
        risk_level_id: riskLevel.id,
        is_phishing: scanResult.isPhishing,
        scan_duration_ms: scanDuration,
      });
      return {
        scanId: scan.id,

        messageScan: scanResult.messageScan,

        findings: scanResult.findings,

        riskScore: scanResult.riskScore,

        riskLevel,

        recommendation: scanResult.recommendation,

        isPhishing: scanResult.isPhishing,

        statistics: scanResult.statistics,
      };
    } catch (error) {
      /**mark scan as failed */
      await ScanModel.markFailed(scan.id);
      throw error;
    }
  }
  /**
   * Get message scan by ID.
   */
  static async getById(id, userId) {
    const messageScan = await MessageScanModel.findById(id);

    if (!messageScan) {
      throw new ApiError(404, "Message scan not found.");
    }
    /** verify user */
    await this.verfiyUser(messageScan.scan_id, userId);

    return messageScan;
  }

  /**
   * Get message scan by parent scan ID.
   */
  static async getByScanId(scanId, userId) {
    const messageScan = await MessageScanModel.findByScanId(scanId);

    if (!messageScan) {
      throw new ApiError(404, "Message scan not found.");
    }
    /** verify user */
    await this.verfiyUser(messageScan.scan_id, userId);
    return messageScan;
  }

  /**
   * Update a message scan.
   */
  static async update(id, data, userId) {
    const exists = await MessageScanModel.findById(id);

    if (!exists) {
      throw new ApiError(404, "Message scan not found.");
    }
    /** verify user */
    await this.verfiyUser(exists.scan_id, userId);
    const updatedMessageScan = await MessageScanModel.update(id, data);
    return updatedMessageScan;
  }

  /**
   * Delete a message scan.
   */
  static async delete(id, userId) {
    const exists = await MessageScanModel.findById(id);

    if (!exists) {
      throw new ApiError(404, "Message scan not found.");
    }
    /** verify user */
    await this.verfiyUser(exists.scan_id, userId);
    return await MessageScanModel.delete(id);
  }
  static async verfiyUser(scanId, userId) {
    const scan = ScanModel.findById(scanId);
    if (!scan) {
      throw new ApiError(
        400,
        "No parent scan available for this message scan.",
      );
    }
    if (scan.user_id && scan.user_id !== userId) {
      throw new ApiError(403, "You are not authorised for this message scan");
    }
    return true;
  }
}

export default MessageScanService;
