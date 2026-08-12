import ApiError from "../utils/ApiError.js";
import AdminScanModel from "../models/adminScanModel.js";

class AdminScanService {
  /**
   * Get platform-wide scan history.
   *
   * Admin can optionally filter by:
   * - userId
   * - scanType
   * - riskLevel
   * - isPhishing
   * - status
   * - from
   * - to
   */
  static async getScans({
    page = 1,
    limit = 20,
    userId = null,
    scanType = null,
    riskLevel = null,
    isPhishing = null,
    status = null,
    from = null,
    to = null,
  }) {
    /*
     * Pagination.
     */
    page = Number(page);
    limit = Number(limit);

    if (!Number.isInteger(page) || page < 1) {
      throw new ApiError(400, "Page must be a positive integer.");
    }

    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw new ApiError(400, "Limit must be between 1 and 100.");
    }

    /*
     * Optional user filter.
     */
    if (userId !== null && userId !== undefined && userId !== "") {
      if (!this.isValidUUID(userId)) {
        throw new ApiError(400, "userId must be a valid UUID.");
      }
    } else {
      userId = null;
    }

    /*
     * Scan type.
     */
    if (scanType !== null && scanType !== undefined && scanType !== "") {
      scanType = String(scanType).trim().toUpperCase();

      if (!["URL", "EMAIL", "MESSAGE"].includes(scanType)) {
        throw new ApiError(
          400,
          "Invalid scan type. Use URL, EMAIL, or MESSAGE.",
        );
      }
    } else {
      scanType = null;
    }

    /*
     * Risk level.
     */
    if (riskLevel !== null && riskLevel !== undefined && riskLevel !== "") {
      riskLevel = String(riskLevel).trim().toUpperCase();

      if (!["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(riskLevel)) {
        throw new ApiError(400, "Invalid risk level.");
      }
    } else {
      riskLevel = null;
    }

    /*
     * Phishing filter.
     */
    if (isPhishing !== null && isPhishing !== undefined && isPhishing !== "") {
      if (
        isPhishing !== true &&
        isPhishing !== false &&
        isPhishing !== "true" &&
        isPhishing !== "false"
      ) {
        throw new ApiError(400, "isPhishing must be true or false.");
      }

      isPhishing = isPhishing === true || isPhishing === "true";
    } else {
      isPhishing = null;
    }

    /*
     * Scan status.
     */
    if (status !== null && status !== undefined && status !== "") {
      status = String(status).trim().toUpperCase();

      if (!["PENDING", "PROCESSING", "COMPLETED", "FAILED"].includes(status)) {
        throw new ApiError(
          400,
          "Invalid scan status. Use PENDING, PROCESSING, COMPLETED, or FAILED.",
        );
      }
    } else {
      status = null;
    }

    /*
     * Date filters.
     */
    from = this.normalizeDate(from, "from");

    to = this.normalizeDate(to, "to");

    /*
     * Validate date range.
     */
    if (from && to) {
      const fromDate = new Date(from);

      const toDate = new Date(to);

      if (fromDate > toDate) {
        throw new ApiError(400, "'from' date cannot be after 'to' date.");
      }
    }

    /*
     * Fetch records and total count
     * concurrently.
     */
    const [scans, total] = await Promise.all([
      AdminScanModel.getScans({
        page,
        limit,
        userId,
        scanType,
        riskLevel,
        isPhishing,
        status,
        from,
        to,
      }),

      AdminScanModel.getScansCount({
        userId,
        scanType,
        riskLevel,
        isPhishing,
        status,
        from,
        to,
      }),
    ]);

    const totalPages = total === 0 ? 0 : Math.ceil(total / limit);

    return {
      scans: scans.map((scan) => this.formatScanItem(scan)),

      pagination: {
        page,
        limit,
        total,
        totalPages,

        hasNextPage: page < totalPages,

        hasPreviousPage: page > 1,
      },

      filters: {
        userId,
        scanType,
        riskLevel,
        isPhishing,
        status,
        from,
        to,
      },
    };
  }

  /**
   * Get complete details of any scan.
   *
   * Admin can inspect any scan.
   */
  static async getScanById(scanId) {
    if (!scanId) {
      throw new ApiError(400, "Scan id is required.");
    }

    if (!this.isValidUUID(scanId)) {
      throw new ApiError(400, "Scan id must be a valid UUID.");
    }

    const result = await AdminScanModel.getScanById(scanId);

    if (!result) {
      throw new ApiError(404, "Scan not found.");
    }

    return this.formatScanDetails(result);
  }

  /**
   * Format one scan in the admin list.
   */
  static formatScanItem(scan) {
    return {
      id: scan.id,

      user: {
        id: scan.user_id,

        fullName: scan.full_name,

        email: scan.email,
      },

      scanType: scan.scan_type,

      input: scan.input,

      status: scan.status,

      riskScore: scan.risk_score !== null ? Number(scan.risk_score) : null,

      riskLevel: scan.risk_level
        ? {
            code: scan.risk_level,

            displayName: scan.risk_level_name,

            color: scan.risk_level_color,
          }
        : null,

      isPhishing: scan.is_phishing,

      scanDurationMs:
        scan.scan_duration_ms !== null ? Number(scan.scan_duration_ms) : null,

      startedAt: scan.started_at,

      completedAt: scan.completed_at,

      createdAt: scan.created_at,
    };
  }

  /**
   * Format complete scan details.
   */
  static formatScanDetails(result) {
    const scan = result.scan;

    return {
      scan: {
        id: scan.id,

        user: {
          id: scan.user_id,

          fullName: scan.full_name,

          email: scan.email,
        },

        scanType: scan.scan_type,

        status: scan.status,

        riskScore: scan.risk_score !== null ? Number(scan.risk_score) : null,

        riskLevel: scan.risk_level
          ? {
              id: scan.risk_level_id,

              code: scan.risk_level,

              displayName: scan.risk_level_name,

              minScore: scan.risk_min_score,

              maxScore: scan.risk_max_score,

              color: scan.risk_level_color,
            }
          : null,

        isPhishing: scan.is_phishing,

        scanDurationMs:
          scan.scan_duration_ms !== null ? Number(scan.scan_duration_ms) : null,

        engineVersion: scan.engine_version,

        startedAt: scan.started_at,

        completedAt: scan.completed_at,

        createdAt: scan.created_at,

        updatedAt: scan.updated_at,
      },

      findings: result.findings.map((finding) => ({
        id: finding.id,

        findingType: finding.finding_type,

        findingValue: finding.finding_value,

        severity: Number(finding.severity),

        score: Number(finding.score),

        description: finding.description,

        source: finding.source,

        evidence: finding.evidence,

        createdAt: finding.created_at,
      })),

      result: this.formatScannerResult(scan.scan_type, result),
    };
  }

  /**
   * Return scanner-specific details.
   */
  static formatScannerResult(scanType, result) {
    if (scanType === "URL") {
      return {
        urlScan: result.urlScan,
      };
    }

    if (scanType === "EMAIL") {
      return {
        emailScan: result.emailScan,
      };
    }

    if (scanType === "MESSAGE") {
      return {
        messageScan: result.messageScan,
      };
    }

    return {};
  }

  /**
   * Normalize date input.
   */
  static normalizeDate(value, fieldName) {
    if (value === null || value === undefined || value === "") {
      return null;
    }

    const valueString = String(value).trim();

    /*
     * YYYY-MM-DD
     */
    if (/^\d{4}-\d{2}-\d{2}$/.test(valueString)) {
      const date = new Date(`${valueString}T00:00:00Z`);

      if (Number.isNaN(date.getTime())) {
        throw new ApiError(400, `Invalid ${fieldName} date.`);
      }

      return valueString;
    }

    /*
     * ISO timestamp.
     */
    const date = new Date(valueString);

    if (Number.isNaN(date.getTime())) {
      throw new ApiError(400, `Invalid ${fieldName} date.`);
    }

    return date.toISOString();
  }

  /**
   * Validate UUID.
   */
  static isValidUUID(value) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value,
    );
  }
}

export default AdminScanService;
