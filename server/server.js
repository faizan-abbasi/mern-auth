import express from "express";
import cors from "cors";
import "dotenv/config";
import cookieParser from "cookie-parser";
import connectDB from "./config/db.js";
import authRouter from "./routes/auth.routes.js";
import userRouter from "./routes/user.routes.js";

const app = express();
const port = process.env.PORT || 5000;
connectDB();

// allowed origins
const allowedOrigins = ["http://localhost:5173"];
// middlewares
app.use(express.json()); // so all the request will be parsed to json
app.use(cookieParser());
app.use(cors({ origin: allowedOrigins, credentials: true })); // so we can send cookies in the response

app.use("/api/auth", authRouter);
app.use("/api/user", userRouter);

app.listen(port, () => {
  console.log("server is running on port", port);
});
