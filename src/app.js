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

app.use("/riskradar/auth", authRoutes);
app.use("/riskradar/user", userRoutes);
app.use("/riskradar/admin", adminRoutes);
//end of routes

app.use(errorHandler);

export default app;
