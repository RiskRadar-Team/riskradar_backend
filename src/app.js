import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import path from "path";
import errorHandler from "./middlewares/errorHandler.js";

const app = express();

const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  "https://riskradar-b6ne97etr-sahitya28s-projects.vercel.app",
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

// Middlewares
app.use(express.json());
app.use(cookieParser());

// Routes
import authRoutes from "./routes/authRoutes.js";
import userRoutes from "./routes/userRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";
import domainRoutes from "./routes/domainRoutes.js";
import urlRoutes from "./routes/urlRoutes.js";
import phishingKeywordRoutes from "./routes/phishingKeywordRoutes.js";
import threatTypeRoutes from "./routes/threatTypeRoutes.js";
import riskLevelRoutes from "./routes/riskLevelRoutes.js";
import keywordCategoryRoutes from "./routes/keywordCategoryRoutes.js";
import scanRoutes from "./routes/scanRoutes.js";
import scanFindingRoutes from "./routes/scanFindingRoutes.js";
import emailScanRoutes from "./routes/emailScanRoutes.js";
import messageScanRoutes from "./routes/messageScanRoutes.js";
import dashboardRoutes from "./routes/dashboardRoutes.js";
import adminUserRoutes from "./routes/adminUserRoutes.js";
import adminDashboardRoutes from "./routes/adminDashboardRoutes.js";
import historyRoutes from "./routes/historyRoutes.js";
import adminScanRoutes from "./routes/adminScanRoutes.js";

app.use("/riskradar/auth", authRoutes);
app.use("/riskradar/user", userRoutes);
app.use("/riskradar/admin", adminRoutes);
app.use("/riskradar/domain", domainRoutes);
app.use("/riskradar/url", urlRoutes);
app.use("/riskradar/keyword", phishingKeywordRoutes);
app.use("/riskradar/threat", threatTypeRoutes);
app.use("/riskradar/risk", riskLevelRoutes);
app.use("/riskradar/keyword-category", keywordCategoryRoutes);
app.use("/riskradar/scan", scanRoutes);
app.use("/riskradar/scan-findings", scanFindingRoutes);
app.use("/riskradar/email-scan", emailScanRoutes);
app.use("/riskradar/scan-message", messageScanRoutes);
app.use("/riskradar/dashboard", dashboardRoutes);
app.use("/riskradar/users", adminUserRoutes);
app.use("/riskradar/admin/dashboard", adminDashboardRoutes);
app.use("/riskradar/history", historyRoutes);
app.use("/riskradar/admin/scans", adminScanRoutes);
//end of routes

app.use(errorHandler);

export default app;
