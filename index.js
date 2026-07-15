import http from "http";
import "./src/config/env.js";
import app from "./src/app.js";
import { initialiseDatabaseTable } from "./src/config/db.js";

const PORT = process.env.PORT || 5000;
const server = http.createServer(app);
server.listen(PORT, () => {
  console.log(`Server is running on port number: ${PORT}`);
});

initialiseDatabaseTable()
  .then(() => {
    console.log("Database Connection Successful");
  })
  .catch((error) => {
    console.error(`Database connection failed: ${error}`);
  });
