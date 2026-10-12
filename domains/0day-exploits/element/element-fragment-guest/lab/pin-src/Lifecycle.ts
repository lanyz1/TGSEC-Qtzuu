// Element Web v1.12.29 (2d90d6b7) apps/web/src/Lifecycle.ts
// Excerpts: loadSession guest fragment, doSetLoggedIn clearStorage, persist, restore.

export async function loadSession(opts: ILoadSessionOpts = {}): Promise<boolean> {
    try {
        let enableGuest = opts.enableGuest || false;
        const guestHsUrl = opts.guestHsUrl;
        const guestIsUrl = opts.guestIsUrl;
        const urlParams = opts.urlParams;
        const defaultDeviceDisplayName = opts.defaultDeviceDisplayName;

        if (enableGuest && !guestHsUrl) {
            logger.warn("Cannot enable guest access: can't determine HS URL to use");
            enableGuest = false;
        }

        if (enableGuest && guestHsUrl && urlParams?.guest?.guest_user_id && urlParams?.guest?.guest_access_token) {
            logger.log("Using guest access credentials");
            await doSetLoggedIn(
                {
                    userId: urlParams.guest.guest_user_id,
                    accessToken: urlParams.guest.guest_access_token,
                    homeserverUrl: guestHsUrl,
                    identityServerUrl: guestIsUrl,
                    guest: true,
                },
                true,
                false,
            );
            return true;
        }
        const success = await restoreSessionFromStorage({
            ignoreGuest: Boolean(opts.ignoreGuest),
        });
        if (success) {
            return true;
        }
        if (sessionLockStolen) {
            return false;
        }

        if (enableGuest && guestHsUrl) {
            return registerAsGuest(guestHsUrl, guestIsUrl, defaultDeviceDisplayName);
        }

        // fall back to welcome screen
        return false;
    } catch (e) {
        if (opts.abortSignal?.aborted) {
            return false;
        }
        if (e instanceof AbortLoginAndRebuildStorage) {
            return false;
        }
        if (sessionLockStolen) {
            return false;
        }
        return handleLoadSessionFailure(e, opts);
    }
}

async function doSetLoggedIn(
    credentials: IMatrixClientCreds,
    clearStorageEnabled: boolean,
    isFreshLogin: boolean,
): Promise<MatrixClient> {
    checkSessionLock();
    credentials.guest = Boolean(credentials.guest);

    const softLogout = isSoftLogout();

    logger.log(
        "setLoggedIn: mxid: " +
            credentials.userId +
            " deviceId: " +
            credentials.deviceId +
            " guest: " +
            credentials.guest +
            " hs: " +
            credentials.homeserverUrl +
            " softLogout: " +
            softLogout,
        " freshLogin: " + credentials.freshLogin,
    );

    if (clearStorageEnabled) {
        await clearStorage();
    }

    const results = await StorageManager.checkConsistency();
    // remainder starts the Matrix client after the wipe; guest fragment never whoami()s first
}

export async function restoreSessionFromStorage(opts?: { ignoreGuest?: boolean }): Promise<boolean> {
    const ignoreGuest = opts?.ignoreGuest;

    if (!localStorage) {
        return false;
    }

    const { hsUrl, isUrl, hasAccessToken, accessToken, refreshToken, userId, deviceId, isGuest } =
        await getStoredSessionVars();

    if (hasAccessToken && !accessToken) {
        logger.warn(
            "restoreSessionFromStorage: storage indicates we should have an access token, but we do not. Displaying StorageEvictedDialog",
        );
        await abortLogin();
    }

    if (accessToken && userId && hsUrl) {
        if (ignoreGuest && isGuest) {
            logger.log("Ignoring stored guest account: " + userId);
            return false;
        }

        logger.log(`Restoring session for ${userId}`);
        await doSetLoggedIn(
            {
                userId: userId,
                deviceId: deviceId,
                accessToken: decryptedAccessToken,
                refreshToken: decryptedRefreshToken,
                homeserverUrl: hsUrl,
                identityServerUrl: isUrl,
                guest: isGuest,
                pickleKey: pickleKey ?? undefined,
                freshLogin: freshLogin,
            },
            false,
            freshLogin,
        );
        return true;
    } else {
        logger.log("No previous session found.");
        return false;
    }
}

async function persistCredentials(credentials: IMatrixClientCreds): Promise<void> {
    localStorage.setItem(HOMESERVER_URL_KEY, credentials.homeserverUrl);
    if (credentials.identityServerUrl) {
        localStorage.setItem(ID_SERVER_URL_KEY, credentials.identityServerUrl);
    }
    localStorage.setItem("mx_user_id", credentials.userId);
    localStorage.setItem("mx_is_guest", JSON.stringify(credentials.guest));

    await persistTokens(credentials.pickleKey, credentials);

    if (credentials.deviceId) {
        localStorage.setItem("mx_device_id", credentials.deviceId);
    }

    logger.log(`Session persisted for ${credentials.userId}`);
}

export async function clearStorage(opts?: { deleteEverything?: boolean }): Promise<void> {
    logger.info(`Clearing storage, deleteEverything=${opts?.deleteEverything}`);

    if (window.localStorage) {
        const language = SettingsStore.getValueAt(SettingLevel.DEVICE, "language", null, true, true);
        const pendingInvites = ThreepidInviteStore.instance.getWireInvites();
        const registrationTime = window.localStorage.getItem("mx_registration_time");

        window.localStorage.clear();

        try {
            await StorageAccess.idbClear("account");
        } catch (e) {
            logger.error("idbClear failed for account", e);
        }

        if (!opts?.deleteEverything) {
            if (language) {
                await SettingsStore.setValue("language", null, SettingLevel.DEVICE, language);
            }
            pendingInvites.forEach(({ roomId, ...invite }) => {
                ThreepidInviteStore.instance.storeInvite(roomId, invite);
            });
            if (registrationTime) {
                window.localStorage.setItem("mx_registration_time", registrationTime);
            }
        }
    }

    window.sessionStorage?.clear();

    const cli = createMatrixClient({
        baseUrl: "",
    });

    await EventIndexPeg.deleteEventIndex();
    await cli.clearStores();
}
