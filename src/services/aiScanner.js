import ai from "../config/gemini.js";
import ApiError from "../utils/ApiError.js";

class AIScanner {
  /**
   * Analyse a message using Gemini AI.
   *
   * The input should contain both the raw message and
   * the signals already extracted by the rule engine.
   */
  static async analyseMessage(messageData) {
    if (!messageData) {
      throw new ApiError(400, "Message data is required.");
    }

    const prompt = `
      You are an expert cybersecurity analyst specializing in phishing and scam detection.

      Analyse the provided message and the extracted security signals.

      Return ONLY valid JSON.

      Do not use markdown.

      Do not add explanations.

      The JSON must match exactly this schema:

      {
        "isPhishing": boolean,
        "confidence": number,
        "riskScore": number,
        "category": string,
        "summary": string,
        "findings":[
          {
            "finding_type": "AI",
            "finding_value": string,
            "severity": number,
            "score": number,
            "description": string
          }
        ]
      }

    Rules:

    - confidence: 0-100
    - riskScore: 0-100
    - severity: 1-5
    - score: 0-100

    Possible categories:

    Credential Theft
    Business Email Compromise
    Financial Fraud
    Tech Support Scam
    Lottery Scam
    Investment Scam
    Government Scam
    Delivery Scam
    Refund Scam
    Romance Scam
    Identity Theft
    UPI Fraud
    Unknown

    Guidelines:

    - Use the extracted signals as evidence.
    - Focus on social engineering, impersonation, urgency, credential theft, financial fraud, and manipulation tactics.
    - Do not duplicate obvious rule-based findings unless they materially increase risk.

  Input:

${JSON.stringify(messageData, null, 2)}
`;

    try {
      const response = await ai.models.generateContent({
        model: process.env.GEMINI_MODEL || "gemini-3.6-flash",
        contents: prompt,
      });

      let text = response.text || "";

      /*
       * Remove markdown code fences if Gemini adds them.
       */
      text = text
        .replace(/\\\`\\\`\\\`json/gi, "")
        .replace(/\\\`\\\`\\\`/g, "")
        .trim();

      const json = JSON.parse(text);

      /*
       * Basic validation.
       */
      if (
        typeof json.isPhishing !== "boolean" ||
        typeof json.confidence !== "number" ||
        typeof json.riskScore !== "number" ||
        !Array.isArray(json.findings)
      ) {
        throw new Error("Invalid AI response schema.");
      }

      /*
       * Normalize findings.
       */
      json.findings = json.findings.map((finding) => ({
        finding_type: "AI",
        finding_value: finding.finding_value || "AI_RISK",
        severity: Math.max(1, Math.min(5, Number(finding.severity) || 3)),
        score: Math.max(0, Math.min(100, Number(finding.score) || 10)),
        description: finding.description || "AI detected suspicious behavior.",
        source: "GEMINI_AI",
        evidence: {
          confidence: json.confidence,
          category: json.category,
        },
      }));

      return {
        isPhishing: json.isPhishing,
        confidence: Math.max(0, Math.min(100, json.confidence)),
        riskScore: Math.max(0, Math.min(100, json.riskScore)),
        category: json.category || "Unknown",
        summary: json.summary || "",
        findings: json.findings,
      };
    } catch (error) {
      console.error("Gemini message analysis failed:", error);

      /*
       * Fail gracefully.
       * The rule engine should still work even if AI fails.
       */
      return {
        isPhishing: false,
        confidence: 0,
        riskScore: 0,
        category: "Unknown",
        summary: "AI analysis unavailable.",
        findings: [],
      };
    }
  }
}
export default AIScanner;

// import ai from "../config/gemini.js";
// import ApiError from "../utils/ApiError.js";

// class AIScanner {

//     /**
//      * Analyse URL.
//      */
//     static async analyseUrl(urlData) {

//     }

//     /**
//      * Analyse Email.
//      */
//     static async analyseEmail(emailData) {

//     }

//     /**
//      * Analyse Message.
//      */
//     static async analyseMessage(messageData) {

//     }

//     /**
//      * Generate Findings.
//      */
//     static generateFindings(aiResponse) {

//     }

// }

// export default AIScanner;
