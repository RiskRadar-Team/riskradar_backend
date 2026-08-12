import { Pool } from "pg";

import pg from "pg";
const { types } = pg;
// OID 1082 = DATE
types.setTypeParser(1082, (value) => value);
//to fix 2026-06-25T18:30:00.000Z to 2026-06-25

//create a connection pool to the database
export const dbPool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

//table creation if not exist
export async function initialiseDatabaseTable() {
  /**user table */
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      full_name VARCHAR(150) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      role VARCHAR(20)
        DEFAULT 'USER'
        CHECK (role IN ('USER','ADMIN')),
      email_verified BOOLEAN DEFAULT FALSE,
      is_active BOOLEAN DEFAULT TRUE,
      last_login TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  /**tokens table */
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,
      token TEXT NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS password_reset_otps (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

        user_id UUID NOT NULL
            REFERENCES users(id)
            ON DELETE CASCADE,

        otp_hash VARCHAR(64) NOT NULL,

        expires_at TIMESTAMP NOT NULL,

        attempts SMALLINT NOT NULL DEFAULT 0
            CHECK (attempts >= 0),

        verified_at TIMESTAMP,

        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_password_reset_otps_user_id
        ON password_reset_otps(user_id);

    CREATE INDEX IF NOT EXISTS idx_password_reset_otps_expires_at
        ON password_reset_otps(expires_at);
    `);
  /**threat types table */
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS threat_types (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      code VARCHAR(50) NOT NULL UNIQUE,
      display_name VARCHAR(100) NOT NULL,
      description TEXT,
      severity SMALLINT
        NOT NULL
        DEFAULT 3
        CHECK (severity BETWEEN 1 AND 5),
      is_active BOOLEAN
        NOT NULL
        DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  /**Insert default values on threat_types table */
  // await dbPool.query(`
  //   INSERT INTO threat_types (code, display_name, description, severity)
  //   VALUES
  //     ('PHISHING','Phishing','Credential stealing websites',5),
  //     ('MALWARE','Malware','Distributes malicious software',5),
  //     ('RANSOMWARE','Ransomware','Encrypts user files for ransom',5),
  //     ('SCAM','Scam','Fraudulent websites or messages',4),
  //     ('SPAM','Spam','Unwanted advertising or spam',2),
  //     ('BOTNET','Botnet','Botnet command and control',5),
  //     ('SPYWARE','Spyware','Collects user information secretly',4),
  //     ('ADWARE','Adware','Displays unwanted advertisements',2),
  //     ('CRYPTO_SCAM','Crypto Scam','Cryptocurrency fraud',5),
  //     ('CREDENTIAL_THEFT','Credential Theft','Attempts to steal usernames/passwords',5),
  //     ('OTHER','Other','Unknown threat type',1)
  //   ON CONFLICT (code) DO NOTHING;
  // `);
  await dbPool.query(`
    INSERT INTO threat_types (code, display_name, description, severity)
    VALUES
      ('PHISHING','Phishing','Credential stealing websites',5),
      ('MALWARE','Malware','Distributes malicious software',5),
      ('RANSOMWARE','Ransomware','Encrypts user files for ransom',5),
      ('SCAM','Scam','Fraudulent websites or messages',4),
      ('SPAM','Spam','Unwanted advertising or spam',2),
      ('BOTNET','Botnet','Botnet command and control',5),
      ('SPYWARE','Spyware','Collects user information secretly',4),
      ('ADWARE','Adware','Displays unwanted advertisements',2),
      ('CRYPTO_SCAM','Crypto Scam','Cryptocurrency fraud',5),
      ('CREDENTIAL_THEFT','Credential Theft','Attempts to steal usernames/passwords',5),
      ('OTHER','Other','Unknown threat type',1),
      ('CRYPTO_MINER','Crypto Miner','Uses system resources to mine cryptocurrency',4),
      ('C2_SERVER','C2 Server','Command and control server for malware/botnets',5),
      ('EXPLOIT_KIT','Exploit Kit','Toolkit used to exploit vulnerabilities',5),
      ('TROJAN','Trojan','Malicious software disguised as legitimate',5),
      ('SUSPICIOUS','Suspicious','Potentially harmful or abnormal activity',3)
    ON CONFLICT (code) DO NOTHING;
  `);

  /**risk_levels table */
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS risk_levels (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      code VARCHAR(20) UNIQUE NOT NULL,
      display_name VARCHAR(50) NOT NULL,
      min_score SMALLINT,
      max_score SMALLINT,
      color VARCHAR(20),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  /**seed default values for risk level table */
  await dbPool.query(`
    INSERT INTO risk_levels 
    (code, display_name, min_score, max_score, color)
    VALUES
      ('SAFE', 'Safe', 0, 19, 'green'),
      ('LOW', 'Low Risk', 20, 39, 'blue'),
      ('MEDIUM', 'Medium Risk', 40, 69, 'yellow'),
      ('HIGH', 'High Risk', 70, 89, 'orange'),
      ('CRITICAL', 'Critical', 90, 100, 'red')
    ON CONFLICT (code) DO NOTHING;
  `);
  /**domains table */
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS domains(
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      domain_name VARCHAR(255) NOT NULL UNIQUE,
      list_type VARCHAR(20)
        NOT NULL
        CHECK (list_type IN ('BLACKLIST', 'WHITELIST')),
      threat_type_id UUID REFERENCES threat_types(id)
      ON DELETE SET NULL,
      reason TEXT,
      source VARCHAR(100),
      confidence_score SMALLINT
        CHECK (confidence_score BETWEEN 0 AND 100),
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_by UUID
        REFERENCES users(id)
        ON DELETE SET NULL,
      updated_by UUID
        REFERENCES users(id)
        ON DELETE SET NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_domains_name
      ON domains(domain_name);
      CREATE INDEX IF NOT EXISTS idx_domains_list_type
      ON domains(list_type);
      CREATE INDEX IF NOT EXISTS idx_domains_active
      ON domains(is_active);
  `);
  /**urls table */
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS urls(
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      url TEXT NOT NULL UNIQUE,
      domain_id UUID
        REFERENCES domains(id)
        ON DELETE SET NULL,
      list_type VARCHAR(20)
        NOT NULL
        CHECK (list_type IN ('BLACKLIST', 'WHITELIST')),
      threat_type_id UUID REFERENCES threat_types(id)
        ON DELETE SET NULL,
      reason TEXT,
      source VARCHAR(100),
      confidence_score SMALLINT
        CHECK (confidence_score BETWEEN 0 AND 100),
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_by UUID
        REFERENCES users(id)
        ON DELETE SET NULL,
      updated_by UUID
        REFERENCES users(id)
        ON DELETE SET NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_urls_domain
      ON urls(domain_id);
      CREATE INDEX IF NOT EXISTS idx_urls_list_type
      ON urls(list_type);
      CREATE INDEX IF NOT EXISTS idx_urls_active
      ON urls(is_active);
      CREATE INDEX IF NOT EXISTS idx_urls_created_at
      ON urls(created_at);
  `);
  /**keyword category table */
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS keyword_categories (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      code VARCHAR(50) UNIQUE NOT NULL,
      display_name VARCHAR(100) NOT NULL,
      description TEXT,
      default_severity SMALLINT,
      color VARCHAR(20),
      icon VARCHAR(255),
      is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  /**insert default keyword categories */
  await dbPool.query(`
    INSERT INTO keyword_categories (code, display_name, description, default_severity, color, icon)
    VALUES
      ('BANKING','Banking','Keywords related to banking and financial institutions',5,'#1E90FF','bank'),
      ('PAYMENT','Payment','Keywords related to online payments and transactions',4,'#32CD32','credit-card'),
      ('SOCIAL','Social','Keywords related to social media platforms',3,'#FF69B4','users'),
      ('EMAIL','Email','Keywords related to email services and communication',3,'#FFD700','envelope'),
      ('CRYPTO','Crypto','Keywords related to cryptocurrency and blockchain',5,'#8A2BE2','bitcoin'),
      ('SHOPPING','Shopping','Keywords related to e-commerce and online shopping',2,'#FF4500','shopping-cart'),
      ('GOVERNMENT','Government','Keywords related to government services and agencies',4,'#2E8B57','building'),
      ('TECH','Tech','Keywords related to technology and IT services',3,'#00CED1','laptop'),
      ('MALWARE','Malware','Keywords related to malicious software and cyber threats',5,'#DC143C','bug'),
      ('OTHER','Other','Miscellaneous or uncategorized keywords',1,'#808080','question')
    ON CONFLICT (code) DO NOTHING;
  `);
  /**phishing keyword table */
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS phishing_keywords(
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      keyword VARCHAR(255) NOT NULL UNIQUE,
      category_id UUID NOT NULL
        REFERENCES keyword_categories(id)
        ON DELETE RESTRICT,
      severity SMALLINT
        NOT NULL
        DEFAULT 3
        CHECK (severity BETWEEN 1 AND 5),
      match_type VARCHAR(20)
        NOT NULL
        DEFAULT 'CONTAINS'
        CHECK (
            match_type IN (
                'EXACT',
                'CONTAINS',
                'REGEX'
            )
        ),
    score SMALLINT
        NOT NULL
        DEFAULT 10
        CHECK (score BETWEEN 0 AND 100),
    description TEXT,
    example TEXT,
    is_case_sensitive BOOLEAN
        NOT NULL
        DEFAULT FALSE,
    language VARCHAR(10)
      NOT NULL
      DEFAULT 'en',
    is_active BOOLEAN
        NOT NULL
        DEFAULT TRUE,
    created_by UUID
        REFERENCES users(id)
        ON DELETE SET NULL,
    updated_by UUID
        REFERENCES users(id)
        ON DELETE SET NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_keywords_keyword
    ON phishing_keywords(keyword);

    CREATE INDEX IF NOT EXISTS idx_keywords_category
    ON phishing_keywords(category_id);

    CREATE INDEX IF NOT EXISTS idx_keywords_severity
    ON phishing_keywords(severity);

    CREATE INDEX IF NOT EXISTS idx_keywords_active
    ON phishing_keywords(is_active);

    CREATE INDEX IF NOT EXISTS idx_keywords_match_type
    ON phishing_keywords(match_type);
  `);
  await dbPool.query(`
      CREATE TABLE IF NOT EXISTS scans (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID
            REFERENCES users(id)
            ON DELETE SET NULL,
        scan_type VARCHAR(20)
            NOT NULL
            CHECK (
                scan_type IN (
                    'URL',
                    'EMAIL',
                    'MESSAGE'
                )
            ),
        status VARCHAR(20)
            NOT NULL
            DEFAULT 'PENDING'
            CHECK (
                status IN (
                    'PENDING',
                    'PROCESSING',
                    'COMPLETED',
                    'FAILED'
                )
            ),
        risk_score SMALLINT
            CHECK (risk_score BETWEEN 0 AND 100),
        risk_level_id  UUID REFERENCES risk_levels(id)
            ON DELETE SET NULL,
        is_phishing BOOLEAN,
        scan_duration_ms INTEGER,
        engine_version VARCHAR(20),
        started_at TIMESTAMP,
        completed_at TIMESTAMP,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_scans_user
      ON scans(user_id);
      CREATE INDEX IF NOT EXISTS idx_scans_type
      ON scans(scan_type);
      CREATE INDEX IF NOT EXISTS idx_scans_status
      ON scans(status);
      CREATE INDEX IF NOT EXISTS idx_scans_created_at
      ON scans(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_scans_risk_level
      ON scans(risk_level_id);
      CREATE INDEX IF NOT EXISTS idx_scans_is_phishing
      ON scans(is_phishing);
    `);
  await dbPool.query(`
      CREATE TABLE IF NOT EXISTS url_scans (

      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

      scan_id UUID
          NOT NULL
          UNIQUE
          REFERENCES scans(id)
          ON DELETE CASCADE,

      input_url TEXT NOT NULL,

      normalized_url TEXT NOT NULL,

      final_url TEXT,

      domain_name VARCHAR(255) NOT NULL,

      protocol VARCHAR(20),

      uses_https BOOLEAN NOT NULL DEFAULT FALSE,

      url_length INTEGER,

      hostname_length INTEGER,

      path_length INTEGER,

      query_length INTEGER,

      subdomain_count SMALLINT,

      contains_ip BOOLEAN NOT NULL DEFAULT FALSE,

      contains_shortener BOOLEAN NOT NULL DEFAULT FALSE,

      contains_at_symbol BOOLEAN NOT NULL DEFAULT FALSE,

      contains_hex_encoding BOOLEAN NOT NULL DEFAULT FALSE,

      contains_punycode BOOLEAN NOT NULL DEFAULT FALSE,

      contains_suspicious_tld BOOLEAN NOT NULL DEFAULT FALSE,

      has_non_standard_port BOOLEAN NOT NULL DEFAULT FALSE,

      domain_blacklisted BOOLEAN NOT NULL DEFAULT FALSE,

      url_blacklisted BOOLEAN NOT NULL DEFAULT FALSE,

      reputation_score SMALLINT
          CHECK (reputation_score BETWEEN 0 AND 100),

      google_safe BOOLEAN,

      virustotal_safe BOOLEAN,

      recommendation TEXT,

      api_response JSONB,

      created_at TIMESTAMP
          NOT NULL
          DEFAULT CURRENT_TIMESTAMP,
          
      updated_at TIMESTAMP
          NOT NULL
          DEFAULT CURRENT_TIMESTAMP
    );

      CREATE INDEX IF NOT EXISTS idx_url_scans_domain
      ON url_scans(domain_name);

      CREATE INDEX IF NOT EXISTS idx_url_scans_https
      ON url_scans(uses_https);

      CREATE INDEX IF NOT EXISTS idx_url_scans_blacklisted_domain
      ON url_scans(domain_blacklisted);

      CREATE INDEX IF NOT EXISTS idx_url_scans_blacklisted_url
      ON url_scans(url_blacklisted);

      CREATE INDEX IF NOT EXISTS idx_url_scans_reputation
      ON url_scans(reputation_score);  
  `);
  /** scan findings table */
  await dbPool.query(`
        CREATE TABLE IF NOT EXISTS scan_findings (

          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          scan_id UUID NOT NULL
              REFERENCES scans(id)
              ON DELETE CASCADE,
          finding_type VARCHAR(30)
              NOT NULL
              CHECK (
                  finding_type IN (
                      'DOMAIN',
                      'URL',
                      'KEYWORD',
                      'HEADER',
                      'LINK',
                      'AI',
                      'REPUTATION',
                      'OTHER'
                  )
              ),
          finding_value TEXT NOT NULL,
          severity SMALLINT
              NOT NULL
              DEFAULT 3
              CHECK (severity BETWEEN 1 AND 5),
          score SMALLINT
              NOT NULL
              DEFAULT 0
              CHECK (score BETWEEN 0 AND 100),
          description TEXT,
          source VARCHAR(50),
          evidence JSONB,
          created_at TIMESTAMP
              NOT NULL
              DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_scan_findings_scan_id
      ON scan_findings(scan_id);

      CREATE INDEX IF NOT EXISTS idx_scan_findings_type
      ON scan_findings(finding_type);

      CREATE INDEX IF NOT EXISTS idx_scan_findings_severity
      ON scan_findings(severity);

      CREATE INDEX IF NOT EXISTS idx_scan_findings_score
      ON scan_findings(score);
  `);

  await dbPool.query(`
      CREATE TABLE IF NOT EXISTS email_scans (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        scan_id UUID UNIQUE NOT NULL
            REFERENCES scans(id)
            ON DELETE CASCADE,
        sender_email TEXT,
        sender_domain VARCHAR(255),
        reply_to TEXT,
        return_path TEXT,
        subject TEXT,
        body TEXT,
        suspicious_links TEXT[],
        suspicious_keywords TEXT[],
        attachment_found BOOLEAN,
        urgency_detected BOOLEAN,
        credential_request BOOLEAN,
        spoof_detected BOOLEAN,
        spf_result VARCHAR(20),
        dkim_result VARCHAR(20),
        dmarc_result VARCHAR(20),
        ai_summary TEXT,
        api_response JSONB,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);
  await dbPool.query(`
        CREATE TABLE IF NOT EXISTS message_scans (

          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          scan_id UUID UNIQUE NOT NULL
              REFERENCES scans(id)
              ON DELETE CASCADE,
          platform VARCHAR(30)
              CHECK (
                  platform IN (
                      'SMS',
                      'WHATSAPP',
                      'TELEGRAM',
                      'MESSENGER',
                      'SIGNAL',
                      'DISCORD',
                      'SLACK',
                      'FACEBOOK',
                      'INSTAGRAM',
                      'TWITTER',
                      'LINKEDIN',
                      'SNAPCHAT',
                      'TIKTOK',
                      'OTHER'
                  )
              ),
          sender TEXT,
          sender_id TEXT,
          message TEXT NOT NULL,
          language VARCHAR(20),
          suspicious_links TEXT[],
          suspicious_keywords TEXT[],
          urgency_detected BOOLEAN NOT NULL DEFAULT FALSE,
          credential_request BOOLEAN NOT NULL DEFAULT FALSE,
          financial_request BOOLEAN NOT NULL DEFAULT FALSE,
          impersonation_detected BOOLEAN NOT NULL DEFAULT FALSE,
          shortened_url_detected BOOLEAN NOT NULL DEFAULT FALSE,
          phone_number_detected BOOLEAN NOT NULL DEFAULT FALSE,
          email_detected BOOLEAN NOT NULL DEFAULT FALSE,
          scam_type VARCHAR(100),
          ai_summary TEXT,
          api_response JSONB,
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_message_scans_platform
      ON message_scans(platform);

      CREATE INDEX IF NOT EXISTS idx_message_scans_sender
      ON message_scans(sender);

      CREATE INDEX IF NOT EXISTS idx_message_scans_scam_type
      ON message_scans(scam_type);

      CREATE INDEX IF NOT EXISTS idx_message_scans_urgency
      ON message_scans(urgency_detected);

      CREATE INDEX IF NOT EXISTS idx_message_scans_impersonation
      ON message_scans(impersonation_detected);

      CREATE INDEX IF NOT EXISTS idx_message_scans_created_at
      ON message_scans(created_at)
    `);
  console.log("Database tables initialized successfully");
}
