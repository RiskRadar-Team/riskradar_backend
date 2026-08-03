import ScanFindingModel from "../models/scanFindingModel.js";
import ScanModel from "../models/scanModel.js";
import ApiError from "../utils/ApiError.js";

class ScanFindingService {
  /**create a finding for a scan */
  static async createFinding(scanId, data, userId) {
    if (!scanId) {
      throw new ApiError(400, "Scan ID is required. ");
    }
    if (!data) {
      throw new ApiError(400, "Finding data is required.");
    }
    //check parent scan
    const scan = await ScanModel.findById(scanId);
    if (!scan) {
      throw new ApiError(404, "Scan not found.");
    }
    ///check ownership
    if (userId && scan.user_id !== userId) {
      throw new ApiError(
        403,
        "You are not authorised to add findings to this scan.",
      );
    }
    //findings should only be generated while scan is in processing
    if (scan.status !== "PROCESSING") {
      throw new ApiError(
        400,
        `Findings cannot be added when scan status is ${scan.status}.`,
      );
    }
    if (!data.finding_type) {
      throw new ApiError(400, "Finding type is required.");
    }
    if (!data.finding_value) {
      throw new ApiError(400, "Finding value is required.");
    }
    const finding = await ScanFindingModel.create({
      scan_id: scanId,
      finding_type: data.finding_type,
      finding_value: data.finding_value,
      severity: data.severity,
      score: data.score,
      description: data.description,
      source: data.source,
      evidence: data.evidence,
    });
    return finding;
  }
  /**
   * Get finding by ID
   */
  static async getFindingById(id, userId) {
    if (!id) {
      throw new ApiError(400, "Finding ID is required.");
    }
    const finding = await ScanFindingModel.findById(id);
    if (!finding) {
      throw new ApiError(404, "Finding not found.");
    }
    //check parent scan ownership
    const scan = await ScanModel.findById(finding.scan_id);
    if (!scan) {
      throw new ApiError(404, "Parent scan not found.");
    }
    if (userId && scan.user_id !== userId) {
      throw new ApiError(403, "You are not authorised to access this finding.");
    }
    return finding;
  }
  /**
   * Get all findings for a scan
   *
   */
  static async getFindingsByScanId(scanId, userId) {
    if (!scanId) {
      throw new ApiError(400, "Scan ID is required.");
    }
    const scan = await ScanModel.findById(scanId);
    if (!scan) {
      throw new ApiError(404, "Scan not found.");
    }
    if (userId && scan.user_id !== userId) {
      throw new ApiError(
        403,
        "You are not authorized to access findings for this scan.",
      );
    }
    const findings = await ScanFindingModel.findByScanId(scanId);
    return findings;
  }
  /**
   * Get findings by type
   */
  static async getFindingsByType(scanId, findingType, userId) {
    if (!scanId) {
      throw new ApiError(400, "Scan ID is required.");
    }

    if (!findingType) {
      throw new ApiError(400, "Finding type is required.");
    }

    const scan = await ScanModel.findById(scanId);

    if (!scan) {
      throw new ApiError(404, "Scan not found.");
    }

    if (userId && scan.user_id !== userId) {
      throw new ApiError(
        403,
        "You are not authorized to access findings for this scan.",
      );
    }
    const findings = await ScanFindingModel.findByScanIdAndFindingType(
      scanId,
      findingType,
    );
    return findings;
  }
  /**
   * Get high-risk findings
   */
  static async getHighRiskFindings(scanId, userId) {
    if (!scanId) {
      throw new ApiError(400, "Scan ID is required.");
    }

    const scan = await ScanModel.findById(scanId);

    if (!scan) {
      throw new ApiError(404, "Scan not found.");
    }

    if (userId && scan.user_id !== userId) {
      throw new ApiError(
        403,
        "You are not authorized to access findings for this scan.",
      );
    }

    const findings = await ScanFindingModel.findHighRiskByScanId(scanId);
    return findings;
  }
  /** Get finding summary */
  static async getFindingSummary(scanId, userId) {
    if (!scanId) {
      throw new ApiError(400, "Scan ID is required.");
    }
    const scan = await ScanModel.findById(scanId);
    if (!scan) {
      throw new ApiError(404, "Scan not found.");
    }
    if (userId && scan.user_id !== userId) {
      throw new ApiError(403, "You are not authorised to access this scan.");
    }
    const [totalFindings, totalScore, summary] = await Promise.all([
      ScanFindingModel.countByScanId(scanId),
      ScanFindingModel.getTotalScore(scanId),
      ScanFindingModel.getSummaryByScanId(scanId),
    ]);
    return {
      totalFindings,
      totalScore,
      bytype: summary,
    };
  }
  /**
   * Update a finding
   */
  static async updateFinding(id, data, userId) {
    if (!id) {
      throw new ApiError(400, "Finding ID is required.");
    }

    if (!data || Object.keys(data).length === 0) {
      throw new ApiError(400, "At least one field is required for update.");
    }

    const existingFinding = await ScanFindingModel.findById(id);

    if (!existingFinding) {
      throw new ApiError(404, "Finding not found.");
    }

    const scan = await ScanModel.findById(existingFinding.scan_id);

    if (!scan) {
      throw new ApiError(404, "Parent scan not found.");
    }

    if (userId && scan.user_id !== userId) {
      throw new ApiError(403, "You are not authorized to update this finding.");
    }

    // Findings should be updated after scan completion
    if (scan.status === "COMPLETED") {
      throw new ApiError(
        400,
        "Findings of a completed scan cannot be modified.",
      );
    }

    const updatedFinding = await ScanFindingModel.update(id, data);

    return updatedFinding;
  }
  /**
   * Delete a finding
   */
  static async deleteFinding(id, userId) {
    if (!id) {
      throw new ApiError(400, "Finding ID is required.");
    }

    const existingFinding = await ScanFindingModel.findById(id);

    if (!existingFinding) {
      throw new ApiError(404, "Finding not found.");
    }

    const scan = await ScanModel.findById(existingFinding.scan_id);

    if (!scan) {
      throw new ApiError(404, "Parent scan not found.");
    }

    if (userId && scan.user_id !== userId) {
      throw new ApiError(403, "You are not authorized to delete this finding.");
    }

    if (scan.status === "COMPLETED") {
      throw new ApiError(
        400,
        "Findings of a completed scan cannot be deleted.",
      );
    }

    const deletedFinding = await ScanFindingModel.delete(id);

    if (!deletedFinding) {
      throw new ApiError(404, "Finding not found.");
    }

    return deletedFinding;
  }
  /**
   * Delete all findings for a scan
   */
  static async deleteFindingsByScanId(scanId, userId) {
    if (!scanId) {
      throw new ApiError(400, "Scan ID is required.");
    }

    const scan = await ScanModel.findById(scanId);

    if (!scan) {
      throw new ApiError(404, "Scan not found.");
    }

    if (userId && scan.user_id !== userId) {
      throw new ApiError(
        403,
        "You are not authorised to delete findings for this scan.",
      );
    }

    if (scan.status === "COMPLETED") {
      throw new ApiError(
        400,
        "Findings of a completed scan cannot be deleted.",
      );
    }

    const deletedFindings = await ScanFindingModel.deleteByScanId(scanId);
    return deletedFindings;
  }
}

export default ScanFindingService;
