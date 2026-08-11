import ApiError from "../utils/ApiError.js";
import HistoryModel from "../models/historyModel.js";

class HistoryService {
  /**
   * Get authenticated user's scan history.
   *
   * @param {Object} params
   * @param {string} params.userId
   * @param {number|string} params.page
   * @param {number|string} params.limit
   * @param {string|null} params.scanType
   * @param {string|null} params.riskLevel
   * @param {boolean|string|null} params.isPhishing
   * @param {string|null} params.from
   * @param {string|null} params.to
   */
  static async getHistory({
    userId,
    page = 1,
    limit = 20,
    scanType = null,
    riskLevel = null,
    isPhishing = null,
    from = null,
    to = null,
  }) {
    /*
     * Validate authenticated user.
     */
    if (!userId) {
      throw new ApiError(401, "Authenticated user is required.");
    }

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
     *
     * Query parameters arrive as strings.
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
     * Validate date range.
     */
    from = this.normalizeDate(from, "from");

    to = this.normalizeDate(to, "to");

    /*
     * Make sure the date range is valid.
     */
    if (from && to) {
      const fromDate = new Date(from);

      const toDate = new Date(to);

      if (fromDate > toDate) {
        throw new ApiError(400, "'from' date cannot be after 'to' date.");
      }
    }

    /*
     * Fetch history and total count
     * concurrently.
     */
    const [history, total] = await Promise.all([
      HistoryModel.getHistory({
        userId,
        page,
        limit,
        scanType,
        riskLevel,
        isPhishing,
        from,
        to,
      }),

      HistoryModel.getHistoryCount({
        userId,
        scanType,
        riskLevel,
        isPhishing,
        from,
        to,
      }),
    ]);

    const totalPages = total === 0 ? 0 : Math.ceil(total / limit);

    return {
      history: history.map((item) => this.formatHistoryItem(item)),

      pagination: {
        page,
        limit,
        total,
        totalPages,

        hasNextPage: page < totalPages,

        hasPreviousPage: page > 1,
      },

      filters: {
        scanType,
        riskLevel,
        isPhishing,
        from,
        to,
      },
    };
  }

  /**
   * Get one complete historical scan.
   *
   * The model itself verifies that the scan
   * belongs to the authenticated user.
   */
  static async getScanById(userId, scanId) {
    if (!userId) {
      throw new ApiError(401, "Authenticated user is required.");
    }

    if (!scanId) {
      throw new ApiError(400, "Scan id is required.");
    }

    /*
     * Validate UUID.
     */
    if (!this.isValidUUID(scanId)) {
      throw new ApiError(400, "Scan id must be a valid UUID.");
    }

    const result = await HistoryModel.getScanById(userId, scanId);

    if (!result) {
      throw new ApiError(404, "Scan history not found.");
    }

    return this.formatScanDetails(result);
  }

  /**
   * Format one history list item.
   */
  static formatHistoryItem(item) {
    return {
      id: item.id,

      scanType: item.scan_type,

      status: item.status,

      input: item.input,

      riskScore: item.risk_score !== null ? Number(item.risk_score) : null,

      riskLevel: item.risk_level
        ? {
            code: item.risk_level,

            displayName: item.risk_level_name,

            color: item.risk_level_color,
          }
        : null,

      isPhishing: item.is_phishing,

      scanDurationMs:
        item.scan_duration_ms !== null ? Number(item.scan_duration_ms) : null,

      startedAt: item.started_at,

      completedAt: item.completed_at,

      createdAt: item.created_at,
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
   * Format scanner-specific result.
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
   *
   * Accepts:
   * YYYY-MM-DD
   * ISO date strings
   */
  static normalizeDate(value, fieldName) {
    if (value === null || value === undefined || value === "") {
      return null;
    }

    const valueString = String(value).trim();

    /*
     * Accept YYYY-MM-DD directly.
     */
    if (/^\d{4}-\d{2}-\d{2}$/.test(valueString)) {
      const date = new Date(`${valueString}T00:00:00Z`);

      if (Number.isNaN(date.getTime())) {
        throw new ApiError(400, `Invalid ${fieldName} date.`);
      }

      return valueString;
    }

    /*
     * Accept valid ISO timestamps.
     */
    const date = new Date(valueString);

    if (Number.isNaN(date.getTime())) {
      throw new ApiError(400, `Invalid ${fieldName} date.`);
    }

    return date.toISOString();
  }

  /**
   * UUID validation.
   */
  static isValidUUID(value) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value,
    );
  }
}

export default HistoryService;
