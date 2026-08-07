import { dbPool } from "../config/db.js";

class MessageScanModel {
  /** Create a new message scan */
  static async create(data) {
    try {
      const query = `
        INSERT INTO message_scans(
        scan_id, platform, sender, sender_id,
        message, language, suspicious_links, suspicious_keywords,
        urgency_detected, credential_request, financial_request,
        impersonation_detected, shortened_url_detected, phone_number_detected,
        email_detected, scam_type, ai_summary, api_response
        ) VALUES (
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
          $11,$12,$13,$14,$15,$16,$17,$18
        )
        RETURNING *;
      `;
      const values = [
        data.scan_id,
        data.platform,
        data.sender,
        data.sender_id,
        data.message,
        data.language,
        data.suspicious_links,
        data.suspicious_keywords,
        data.urgency_detected,
        data.credential_request,
        data.financial_request,
        data.impersonation_detected,
        data.shortened_url_detected,
        data.phone_number_detected,
        data.email_detected,
        data.scam_type,
        data.ai_summary,
        data.api_response,
      ];
      const { rows } = await dbPool.query(query, values);
      return rows[0];
    } catch (error) {
      console.log("Error while creating new message scan", error);
      throw error;
    }
  }
  /**find the message scan by it's ID */
  static async findById(id) {
    try {
      const query = `
        SELECT * FROM message_scans
        WHERE id = $1 LIMIT 1;
      `;
      const { rows } = await dbPool.query(query, [id]);
      return rows[0] || null;
    } catch (error) {
      console.log("Error while fetching message scan by it's ID", error);
      throw error;
    }
  }
  /**find the message scan by it's scan id */
  static async findByScanId(scanId) {
    try {
      const query = `
        SELECT * FROM message_scans
        WHERE scan_id = $1 LIMIT 1;
      `;
      const { rows } = await dbPool.query(query, [scanId]);
      return rows[0] || null;
    } catch (error) {
      console.log("Error while fetching message scan by it's scan ID", error);
      throw error;
    }
  }
  /**update message scan by it's id */
  static async update(id, data) {
    try {
      const query = `
        UPDATE message_scans
        SET platform=COALESCE($2, platform), sender=COALESCE($3,sender), sender_id= COALESCE($4,sender_id),
        message=COALESCE($5, message), language=COALESCE($6, language), suspicious_links=COALESCE($7,suspicious_links),
        suspicious_keywords=COALESCE($8,suspicious_keywords ),
        urgency_detected=COALESCE($9,urgency_detected ), credential_request=COALESCE($10, credential_request),
         financial_request=COALESCE($11, financial_request),
        impersonation_detected=COALESCE($12, impersonation_detected), shortened_url_detected=COALESCE($13, shortened_url_detected),
        phone_number_detected=COALESCE($14,phone_number_detected ), email_detected=COALESCE($15,email_detected ),
         scam_type=COALESCE($16, scam_type),
        ai_summary=COALESCE($17, ai_summary), api_response=COALESCE($18, api_response),
        updated_at= CURRENT_TIMESTAMP
        WHERE id=$1 RETURNING *;
      `;
      const values = [
        id,
        data.platform,
        data.sender,
        data.sender_id,
        data.message,
        data.language,
        data.suspicious_links,
        data.suspicious_keywords,
        data.urgency_detected,
        data.credential_request,
        data.financial_request,
        data.impersonation_detected,
        data.shortened_url_detected,
        data.phone_number_detected,
        data.email_detected,
        data.scam_type,
        data.ai_summary,
        data.api_response,
      ];
      const { rows } = await dbPool.query(query, values);
      return rows[0] || null;
    } catch (error) {
      console.log("Error while update the message scan", error);
      throw error;
    }
  }
  /** delete message scan by it's id */
  static async delete(id) {
    try {
      const query = `
        DELETE FROM message_scans
        WHERE id = $1
        RETURNING *;
      `;
      const { rows } = await dbPool.query(query, [id]);
      return rows[0] || null;
    } catch (error) {
      console.log("Error while deleting message scan", error);
      throw error;
    }
  }
}
export default MessageScanModel;
