import express from "express";
import cors from "cors";
import "dotenv/config";
import cookieParser from "cookie-parser";
import connectDB from "./config/db.js";
import authRouter from "./routes/auth.routes.js";

const app = express();
const port = process.env.PORT || 5000;
connectDB();

// middlewares
app.use(express.json()); // so all the request will be parsed to json
app.use(cookieParser());
app.use(cors({ credentials: true })); // so we can send cookies in the response

app.use("/api/auth", authRouter);

app.listen(port, () => {
  console.log("server is running on port", port);
});
