// Element Web v1.12.29 (2d90d6b7) apps/web/src/components/structures/MatrixChat.tsx
// initSession comment: "If we have a guest access token in the query params, use that"
// before restoring local storage. loadSession forwards enableGuest + guestHsUrl.

    private async initSession(): Promise<void> {
        if (Lifecycle.isSoftLogout()) {
            void Lifecycle.loadSession({ abortSignal: this.loadSessionAbortController.signal });
            return;
        }

        const delegatedAuthSucceeded = await Lifecycle.attemptDelegatedAuthLogin(
            this.props.urlParams,
            this.props.defaultDeviceDisplayName,
            this.getFragmentAfterLogin(),
        );

        if (delegatedAuthSucceeded) {
            this.tokenLogin = true;
            await Lifecycle.restoreSessionFromStorage({ ignoreGuest: true });
            await this.postLoginSetup();
            return;
        }

        const firstScreen = this.screenAfterLogin ? this.screenAfterLogin.screen : null;
        const restoreSuccess = await this.loadSession();
        if (restoreSuccess) {
            return;
        }

        if (firstScreen !== null && AUTH_SCREENS.includes(firstScreen)) {
            this.showScreenAfterLogin();
        }
    }

    private loadSession(): Promise<boolean> {
        return Promise.resolve()
            .then(() => {
                return Lifecycle.loadSession({
                    urlParams: this.props.urlParams,
                    enableGuest: this.props.enableGuest,
                    guestHsUrl: this.getServerProperties().serverConfig.hsUrl,
                    guestIsUrl: this.getServerProperties().serverConfig.isUrl,
                    defaultDeviceDisplayName: this.props.defaultDeviceDisplayName,
                    abortSignal: this.loadSessionAbortController.signal,
                });
            })
            .then((loadedSession) => {
                if (!loadedSession) {
                    dis.dispatch({ action: "view_welcome_page" });
                }
                return loadedSession;
            });
    }
