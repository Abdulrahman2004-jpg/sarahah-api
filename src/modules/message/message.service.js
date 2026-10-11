import { asyncHandler, successResponse } from "../../utils/response.js";
import * as DBService from "../../DB/db.service.js";
import { UserModel } from "../../DB/models/User.models.js";
import { uploadFiles } from "../../utils/multer/cloudinary.js";
import { MessageModel } from "../../DB/models/Message.model.js";

export const sendMessage = asyncHandler(async (req, res, next) => {
    if (!req.body.content && !req.files?.length) {
        return next(new Error("Message content or attachment is required", { cause: 400 }));
    }

    const { receiverId } = req.params;

    const recipient = await DBService.findOne({
        model: UserModel,
        filter: {
            _id: receiverId,
            deletedAt: { $exists: false },
            confirmEmail: { $exists: true }
        }
    });

    if (!recipient) {
        return next(new Error("Recipient user not found", { cause: 404 }));
    }

    const { content } = req.body;
    let attachments = [];

    if (req.files?.length) {
        attachments = await uploadFiles({
            files: req.files,
            path: `messages/${receiverId}`
        });
    }

    const [message] = await DBService.create({
        model: MessageModel,
        data: [{
            content,
            attachments,
            receiverId,
            senderId: req.user?._id
        }]
    });

    return successResponse({ res, status: 201, data: { message } });
});