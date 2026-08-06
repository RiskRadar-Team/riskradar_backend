import { dbPool } from "../config/db.js";

class EmailScanModel {
  /**
   * Create a new email scan record.
   */
  static async create({
    scan_id,
    sender_email = null,
    sender_domain = null,
    reply_to = null,
    return_path = null,
    subject = null,
    body = null,
    suspicious_links = [],
    suspicious_keywords = [],
    attachment_found = false,
    urgency_detected = false,
    credential_request = false,
    spoof_detected = false,
    spf_result = null,
    dkim_result = null,
    dmarc_result = null,
    ai_summary = null,
    api_response = null,
  }) {
    try {
      const query = `
        INSERT INTO email_scans (
          scan_id,
          sender_email,
          sender_domain,
          reply_to,
          return_path,
          subject,
          body,
          suspicious_links,
          suspicious_keywords,
          attachment_found,
          urgency_detected,
          credential_request,
          spoof_detected,
          spf_result,
          dkim_result,
          dmarc_result,
          ai_summary,
          api_response
        )
        VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8,
          $9, $10, $11, $12, $13, $14, $15,
          $16, $17, $18
        )
        RETURNING *;
      `;

      const values = [
        scan_id,
        sender_email,
        sender_domain,
        reply_to,
        return_path,
        subject,
        body,
        suspicious_links,
        suspicious_keywords,
        attachment_found,
        urgency_detected,
        credential_request,
        spoof_detected,
        spf_result,
        dkim_result,
        dmarc_result,
        ai_summary,
        api_response,
      ];

      const { rows } = await dbPool.query(query, values);

      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }

  /**
   * Find email scan by ID.
   */
  static async findById(id) {
    try {
      const query = `
        SELECT *
        FROM email_scans
        WHERE id = $1
        LIMIT 1;
      `;

      const { rows } = await dbPool.query(query, [id]);

      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }

  /**
   * Find email scan by parent scan ID.
   */
  static async findByScanId(scanId) {
    try {
      const query = `
        SELECT *
        FROM email_scans
        WHERE scan_id = $1
        LIMIT 1;
      `;

      const { rows } = await dbPool.query(query, [scanId]);

      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }

  /**
   * Update an email scan.
   */
  static async update(
    id,
    {
      sender_email,
      sender_domain,
      reply_to,
      return_path,
      subject,
      body,
      suspicious_links,
      suspicious_keywords,
      attachment_found,
      urgency_detected,
      credential_request,
      spoof_detected,
      spf_result,
      dkim_result,
      dmarc_result,
      ai_summary,
      api_response,
    },
  ) {
    try {
      const query = `
        UPDATE email_scans
        SET
          sender_email = COALESCE($2, sender_email),
          sender_domain = COALESCE($3, sender_domain),
          reply_to = COALESCE($4, reply_to),
          return_path = COALESCE($5, return_path),
          subject = COALESCE($6, subject),
          body = COALESCE($7, body),
          suspicious_links = COALESCE($8, suspicious_links),
          suspicious_keywords = COALESCE($9, suspicious_keywords),
          attachment_found = COALESCE($10, attachment_found),
          urgency_detected = COALESCE($11, urgency_detected),
          credential_request = COALESCE($12, credential_request),
          spoof_detected = COALESCE($13, spoof_detected),
          spf_result = COALESCE($14, spf_result),
          dkim_result = COALESCE($15, dkim_result),
          dmarc_result = COALESCE($16, dmarc_result),
          ai_summary = COALESCE($17, ai_summary),
          api_response = COALESCE($18, api_response),
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *;
      `;

      const values = [
        id,
        sender_email,
        sender_domain,
        reply_to,
        return_path,
        subject,
        body,
        suspicious_links,
        suspicious_keywords,
        attachment_found,
        urgency_detected,
        credential_request,
        spoof_detected,
        spf_result,
        dkim_result,
        dmarc_result,
        ai_summary,
        api_response,
      ];

      const { rows } = await dbPool.query(query, values);

      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }

  /**
   * Delete an email scan.
   */
  static async delete(id) {
    try {
      const query = `
        DELETE FROM email_scans
        WHERE id = $1
        RETURNING *;
      `;

      const { rows } = await dbPool.query(query, [id]);

      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
}

export default EmailScanModel;
