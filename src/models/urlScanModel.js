import { dbPool } from "../config/db.js";

class UrlScanModel {
  /**
   * Create URL scan
   */
  static async create(data) {
    try {
      const query = `
      INSERT INTO url_scans (
        scan_id,
        input_url,
        normalized_url,
        final_url,
        domain_name,
        protocol,
        uses_https,
        url_length,
        hostname_length,
        path_length,
        query_length,
        subdomain_count,
        contains_ip,
        contains_shortener,
        contains_at_symbol,
        contains_hex_encoding,
        contains_punycode,
        contains_suspicious_tld,
        has_non_standard_port,
        domain_blacklisted,
        url_blacklisted,
        reputation_score,
        google_safe,
        virustotal_safe,
        recommendation,
        api_response
      )
      VALUES (
        $1, $2, $3, $4, $5,
        $6, $7, $8, $9, $10,
        $11, $12, $13, $14, $15,
        $16, $17, $18, $19, $20,
        $21, $22, $23, $24, $25,
        $26
      )
      RETURNING *;
    `;

      const values = [
        data.scan_id,
        data.input_url,
        data.normalized_url,
        data.final_url ?? null,
        data.domain_name,
        data.protocol ?? null,
        data.uses_https ?? false,
        data.url_length ?? null,
        data.hostname_length ?? null,
        data.path_length ?? null,
        data.query_length ?? null,
        data.subdomain_count ?? null,
        data.contains_ip ?? false,
        data.contains_shortener ?? false,
        data.contains_at_symbol ?? false,
        data.contains_hex_encoding ?? false,
        data.contains_punycode ?? false,
        data.contains_suspicious_tld ?? false,
        data.has_non_standard_port ?? false,
      ];

      const { rows } = await dbPool.query(query, values);

      return rows[0];
    } catch (error) {
      console.error("Error creating URL scan:", error);
      throw error;
    }
  }
  /** find scan by it's id */
  static async findById(scanId) {
    try {
      const query = `
        SELECT * FROM url_scans WHERE scan_id = $1;
      `;
      const values = [scanId];

      const { rows } = await dbPool.query(query, values);

      return rows[0];
    } catch (error) {
      console.error("Error finding URL scan:", error);
      throw error;
    }
  }
  /**find url scan by the scan ID */
  static async findByScanId(scanId) {
    try {
      const query = `
        SELECT * FROM url_scans WHERE scan_id = $1;
      `;
      const values = [scanId];
      const { rows } = await dbPool.query(query, values);

      return rows[0];
    } catch (error) {
      console.error("Error finding URL scan by scan ID:", error);
      throw error;
    }
  }
  /** find url scan by normalised url */
  static async findByNormalizedUrl(normalizedUrl) {
    try {
      const query = `
        SELECT * FROM url_scans 
        WHERE normalized_url = $1
        ORDER BY created_at DESC
        ;
      `;
      const values = [normalizedUrl];
      const { rows } = await dbPool.query(query, values);

      return rows;
    } catch (error) {
      console.error("Error finding URL scan by normalized URL:", error);
      throw error;
    }
  }
  /** find url scan by the domain name and user */
  static async findByDomainNameAndUser(domainName, userId) {
    try {
      const query = `
        SELECT url_scans.*,scans.user_id 
        FROM url_scans
        LEFT JOIN scans
        ON url_scans.scan_id =  scans.id
        WHERE domain_name = $1 AND scans.user_id = $2
        ORDER BY url_scans.created_at DESC;
      `;
      const values = [domainName, userId];
      const { rows } = await dbPool.query(query, values);

      return rows;
    } catch (error) {
      console.error("Error finding URL scan by domain name:", error);
      throw error;
    }
  }
  /** find url scan by the domain name */
  static async findByDomainName(domainName) {
    try {
      const query = `
        SELECT * FROM url_scans
        WHERE domain_name = $1 
        ORDER BY created_at DESC;
      `;
      const values = [domainName];
      const { rows } = await dbPool.query(query, values);

      return rows[0];
    } catch (error) {
      console.error("Error finding URL scan by domain name:", error);
      throw error;
    }
  }
  /**update url scan */
  static async update(scanId, data) {
    try {
      const query = `
        UPDATE url_scans
        SET
          
          final_url = COALESCE($1,final_url),
          domain_name = COALESCE($2,domain_name),
          protocol = COALESCE($3,protocol),
          uses_https = COALESCE($4,uses_https),
          url_length = COALESCE($5,url_length),
          hostname_length = COALESCE($6,hostname_length),
          path_length = COALESCE($7,path_length),
          query_length = COALESCE($8,query_length),
          subdomain_count = COALESCE($9,subdomain_count),
          contains_ip = COALESCE($10,contains_ip),
          contains_shortener = COALESCE($11,contains_shortener),
          contains_at_symbol = COALESCE($12,contains_at_symbol),
          contains_hex_encoding = COALESCE($13,contains_hex_encoding),
          contains_punycode = COALESCE($14,contains_punycode),
          contains_suspicious_tld = COALESCE($15,contains_suspicious_tld),
          has_non_standard_port = COALESCE($16,has_non_standard_port),
          domain_blacklisted = COALESCE($17,domain_blacklisted),
          url_blacklisted = COALESCE($18,url_blacklisted),
          reputation_score = COALESCE($19,reputation_score),
          google_safe = COALESCE($20,google_safe),
          virustotal_safe = COALESCE($21,virustotal_safe),
          recommendation = COALESCE($22,recommendation),
          api_response = COALESCE($23,api_response),
          updated_at = CURRENT_TIMESTAMP
        WHERE scan_id = $24
        RETURNING *;
      `;
      const values = [
        data.final_url ?? null,
        data.domain_name ?? null,
        data.protocol ?? null,
        data.uses_https ?? false,
        data.url_length ?? null,
        data.hostname_length ?? null,
        data.path_length ?? null,
        data.query_length ?? null,
        data.subdomain_count ?? null,
        data.contains_ip ?? false,
        data.contains_shortener ?? false,
        data.contains_at_symbol ?? false,
        data.contains_hex_encoding ?? false,
        data.contains_punycode ?? false,
        data.contains_suspicious_tld ?? false,
        data.has_non_standard_port ?? false,
        data.domain_blacklisted ?? null,
        data.url_blacklisted ?? null,
        data.reputation_score ?? null,
        data.google_safe ?? null,
        data.virustotal_safe ?? null,
        data.recommendation ?? null,
        data.api_response ?? null,
        scanId,
      ];
      const { rows } = await dbPool.query(query, values);
      return rows[0];
    } catch (error) {
      console.error("Error updating URL scan:", error);
      throw error;
    }
  }
  /** delete url scan data */
  static async delete(scanId) {
    try {
      const query = `
        DELETE FROM url_scans
        WHERE scan_id = $1
        RETURNING *;
      `;
      const { rows } = await dbPool.query(query, [scanId]);
      return rows[0];
    } catch (error) {
      console.error("Error deleting URL scan:", error);
      throw error;
    }
  }
  /**count url scans for a domain */
  static async countByDomain(domain) {
    try {
      const query = `
        SELECT COUNT(*) as total
        FROM url_scans
        WHERE domain_name = $1;
      `;
      const {
        rows: [{ total }],
      } = await dbPool.query(query, [domain]);

      return Number(total);
    } catch (error) {
      console.error("Error counting URL scans for domain:", error);
      throw error;
    }
  }

  /**find all url scans */
  static async findAll() {
    try {
      const query = `
        SELECT * FROM url_scans;
      `;
      const { rows } = await dbPool.query(query);
      return rows;
    } catch (error) {
      console.error("Error finding all URL scans:", error);
      throw error;
    }
  }
}

export default UrlScanModel;
