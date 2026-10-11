export const asyncHandler = (fn) => {
    return async (req, res, next) => {
        try {
            await fn(req, res, next);
        } catch (error) {
            error.cause = error.cause || 500;
            return next(error);
        }
    };
};

export const globalErrorHandling = (error, req, res, next) => {
    const status = error.cause || 500;
    return res.status(status).json({
        message: error.message || "Internal server error",
        stack: process.env.NODE_ENV === "development" ? error.stack : undefined
    });
};

export const successResponse = ({ res, status = 200, data = {}, message = "Success" } = {}) => {
    return res.status(status).json({ message, data });
};