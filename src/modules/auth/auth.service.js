import { customAlphabet } from "nanoid";
import { OAuth2Client } from "google-auth-library";

import { providerEnum, UserModel } from "../../DB/models/User.models.js";
import { asyncHandler, successResponse } from "../../utils/response.js";
import { generateHash, compareHash } from "../../utils/security/hash.security.js";
import { generateLoginCredentials } from "../../utils/security/token.security.js";
import { generateEncryption } from "../../utils/security/encryption.security.js";
import { emailEvent } from "../../utils/events/email.event.js";
import * as DBService from "../../DB/db.service.js";

export const signup = asyncHandler(async (req, res, next) => {
    const { fullName, email, password, phone } = req.body;

    const isEmailExist = await DBService.findOne({
        model: UserModel,
        filter: { email }
    });

    if (isEmailExist) {
        return next(new Error("Email already registered", { cause: 409 }));
    }

    const hashPassword = await generateHash({ plaintext: password });
    const encPhone = await generateEncryption({ plaintext: phone });
    const otp = customAlphabet("0123456789", 6)();
    const confirmEmailOtp = await generateHash({ plaintext: otp });

    const [user] = await DBService.create({
        model: UserModel,
        data: [{
            fullName,
            email,
            password: hashPassword,
            phone: encPhone,
            confirmEmailOtp
        }]
    });

    emailEvent.emit("confirmEmail", { to: email, otp });
    return successResponse({ res, status: 201, data: { user } });
});

export const confirmEmail = asyncHandler(async (req, res, next) => {
    const { email, otp } = req.body;

    const user = await DBService.findOne({
        model: UserModel,
        filter: {
            email,
            confirmEmail: { $exists: false },
            confirmEmailOtp: { $exists: true }
        }
    });

    if (!user) {
        return next(new Error("User not found or already verified", { cause: 404 }));
    }

    const isMatch = await compareHash({ plaintext: otp, hashValue: user.confirmEmailOtp });
    if (!isMatch) {
        return next(new Error("Invalid confirmation code", { cause: 400 }));
    }

    const updatedUser = await DBService.updateOne({
        model: UserModel,
        filter: { email },
        data: {
            confirmEmail: Date.now(),
            $unset: { confirmEmailOtp: true },
            $inc: { __v: 1 }
        }
    });

    if (!updatedUser.matchedCount) {
        return next(new Error("Failed to verify email"));
    }

    return successResponse({ res, status: 200, data: {} });
});

export const login = asyncHandler(async (req, res, next) => {
    const { email, password } = req.body;

    const user = await DBService.findOne({
        model: UserModel,
        filter: { email, provider: providerEnum.system }
    });

    if (!user) {
        return next(new Error("Invalid email or password", { cause: 404 }));
    }

    if (!user.confirmEmail) {
        return next(new Error("Please confirm your email first", { cause: 400 }));
    }

    if (user.deletedAt) {
        return next(new Error("This account has been deactivated", { cause: 400 }));
    }

    const isPasswordValid = await compareHash({ plaintext: password, hashValue: user.password });
    if (!isPasswordValid) {
        return next(new Error("Invalid email or password", { cause: 404 }));
    }

    const credentials = await generateLoginCredentials({ user });
    return successResponse({ res, data: { credentials } });
});

export const sendForgotPassword = asyncHandler(async (req, res, next) => {
    const { email } = req.body;
    const otp = customAlphabet("0123456789", 6)();

    const user = await DBService.findOneAndUpdate({
        model: UserModel,
        filter: {
            email,
            confirmEmail: { $exists: true },
            deletedAt: { $exists: false },
            provider: providerEnum.system
        },
        data: {
            forgotPasswordOtp: await generateHash({ plaintext: otp })
        }
    });

    if (!user) {
        return next(new Error("Account not found", { cause: 404 }));
    }

    emailEvent.emit("SendForgotPassword", {
        to: email,
        subject: "Reset Password OTP",
        title: "Reset Password",
        otp
    });

    return successResponse({ res });
});

export const verifyForgotPassword = asyncHandler(async (req, res, next) => {
    const { email, otp } = req.body;

    const user = await DBService.findOne({
        model: UserModel,
        filter: {
            email,
            confirmEmail: { $exists: true },
            deletedAt: { $exists: false },
            forgotPasswordOtp: { $exists: true },
            provider: providerEnum.system
        }
    });

    if (!user) {
        return next(new Error("Account not found", { cause: 404 }));
    }

    const isOtpValid = await compareHash({ plaintext: otp, hashValue: user.forgotPasswordOtp });
    if (!isOtpValid) {
        return next(new Error("Invalid reset code", { cause: 400 }));
    }

    return successResponse({ res });
});

export const resetPassword = asyncHandler(async (req, res, next) => {
    const { email, otp, password } = req.body;

    const user = await DBService.findOne({
        model: UserModel,
        filter: {
            email,
            confirmEmail: { $exists: true },
            deletedAt: { $exists: false },
            forgotPasswordOtp: { $exists: true },
            provider: providerEnum.system
        }
    });

    if (!user) {
        return next(new Error("Account not found", { cause: 404 }));
    }

    const isOtpValid = await compareHash({ plaintext: otp, hashValue: user.forgotPasswordOtp });
    if (!isOtpValid) {
        return next(new Error("Invalid reset code", { cause: 400 }));
    }

    await DBService.updateOne({
        model: UserModel,
        filter: { email },
        data: {
            password: await generateHash({ plaintext: password }),
            changeCredentialsTime: new Date(),
            $unset: { forgotPasswordOtp: 1 }
        }
    });

    return successResponse({ res });
});

async function verifyGoogleAccount({ idToken }) {
    const client = new OAuth2Client();
    const ticket = await client.verifyIdToken({
        idToken,
        audience: process.env.WEB_CLIENT_IDS.split(",")
    });
    return ticket.getPayload();
}

export const signupWithGmail = asyncHandler(async (req, res, next) => {
    const { idToken } = req.body;
    const { picture, name, email, email_verified } = await verifyGoogleAccount({ idToken });

    if (!email_verified) {
        return next(new Error("Google account is not verified", { cause: 400 }));
    }

    const user = await DBService.findOne({
        model: UserModel,
        filter: { email }
    });

    if (user) {
        if (user.provider === providerEnum.google) {
            const credentials = await generateLoginCredentials({ user });
            return successResponse({ res, status: 200, data: { credentials } });
        }
        return next(new Error("Email already registered with another provider", { cause: 409 }));
    }

    const [newUser] = await DBService.create({
        model: UserModel,
        data: [{
            fullName: name,
            email,
            picture,
            confirmEmail: Date.now(),
            provider: providerEnum.google
        }]
    });

    const credentials = await generateLoginCredentials({ user: newUser });
    return successResponse({ res, status: 201, data: { credentials } });
});

export const loginWithGmail = asyncHandler(async (req, res, next) => {
    const { idToken } = req.body;
    const { email, email_verified } = await verifyGoogleAccount({ idToken });

    if (!email_verified) {
        return next(new Error("Google account is not verified", { cause: 400 }));
    }

    const user = await DBService.findOne({
        model: UserModel,
        filter: { email, provider: providerEnum.google }
    });

    if (!user) {
        return next(new Error("User account not found", { cause: 404 }));
    }

    const credentials = await generateLoginCredentials({ user });
    return successResponse({ res, status: 200, data: { credentials } });
});