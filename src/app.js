import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import path from "path";
import errorHandler from "./middlewares/errorHandler.js";

const app = express();

const allowedOrigins = ["http://localhost:5173"];

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
    methods: ["GET", "POST", "PUT", "DELETE"],
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

app.use("/riskradar/auth", authRoutes);
app.use("/riskradar/user", userRoutes);
app.use("/riskradar/admin", adminRoutes);
app.use("/riskradar/domain", domainRoutes);
app.use("/riskradar/url", urlRoutes);
app.use("/riskradar/keyword", phishingKeywordRoutes);
app.use("/riskradar/threat", threatTypeRoutes);
app.use("/riskradar/risk", riskLevelRoutes);
//end of routes

app.use(errorHandler);

export default app;
