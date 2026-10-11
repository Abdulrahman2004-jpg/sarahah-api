import path from "node:path";
import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import { rateLimit } from "express-rate-limit";

import connectDB from "./DB/connection.db.js";
import authController from "./modules/auth/auth.controller.js";
import userController from "./modules/user/user.controller.js";
import messageController from "./modules/message/message.controller.js";
import { globalErrorHandling } from "./utils/response.js";

dotenv.config();

const bootstrap = async () => {
    const app = express();
    const port = process.env.PORT || 5000;

    await connectDB();

    app.use(cors());
    app.use(helmet());

    const limiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        limit: 100,
        message: { message: "Too many requests, please try again later" }
    });

    app.use("/auth", limiter);
    app.use("/uploads", express.static(path.resolve("./src/uploads")));
    app.use(express.json());

    app.get("/", (req, res) => {
        return res.status(200).json({ message: "Sarahah API is running" });
    });

    app.use("/auth", authController);
    app.use("/user", userController);
    app.use("/message", messageController);

    app.all("*", (req, res) => {
        return res.status(404).json({ message: "Route not found" });
    });

    app.use(globalErrorHandling);

    app.listen(port, () => {
        console.log(`Server running on port ${port}`);
    });
};

export default bootstrap;