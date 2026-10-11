import { Router } from "express";
import { auth, authentication } from "../../middleware/authentication.middleware.js";
import { validation } from "../../middleware/validation.middleware.js";
import { cloudFileUpload, fileValidation } from "../../utils/multer/cloud.multer.js";
import { tokenTypeEnum } from "../../utils/security/token.security.js";
import { endpoint } from "./user.authorization.js";
import * as userService from "./user.service.js";
import * as validators from "./user.validation.js";

const router = Router();

router.post("/logout", authentication(), userService.logout);

router.get("/profile", authentication(), userService.profile);

router.get(
    "/refresh-token",
    authentication({ tokenType: tokenTypeEnum.refresh }),
    userService.getNewLoginCredentials
);

router.get(
    "/:userId",
    validation(validators.shareProfile),
    userService.shareProfile
);

router.patch(
    "/password",
    authentication(),
    validation(validators.updatePassword),
    userService.updatePassword
);

router.delete(
    "/:userId",
    auth({ accessRoles: endpoint.deleteAccount }),
    validation(validators.deleteAccount),
    userService.deleteAccount
);

router.delete(
    "/:userId/freeze-account",
    authentication(),
    validation(validators.freezeAccount),
    userService.freezeAccount
);

router.patch(
    "/:userId/restore-account",
    auth({ accessRoles: endpoint.restoreAccount }),
    validation(validators.restoreAccount),
    userService.restoreAccount
);

router.patch(
    "/profile-image",
    authentication(),
    cloudFileUpload({ validation: fileValidation.image }).single("image"),
    validation(validators.profileImage),
    userService.profileImage
);

router.patch(
    "/profile-cover-images",
    authentication(),
    cloudFileUpload({ validation: fileValidation.image }).array("images", 2),
    validation(validators.profileCoverImage),
    userService.profileCoverImage
);

export default router;