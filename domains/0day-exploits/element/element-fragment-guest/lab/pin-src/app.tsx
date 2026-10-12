// Element Web v1.12.29 (2d90d6b7) apps/web/src/vector/app.tsx
// Guests default on: enableGuest={!config.disable_guests}. onTokenLoginCompleted
// strips SSO/OIDC params only, not guest_user_id / guest_access_token.

function onTokenLoginCompleted(urlParams: URLParams, fragmentAfterLogin: string): void {
    const url = new URL(window.location.href);

    for (const param in { ...urlParams.legacy_sso }) {
        url.searchParams.delete(param);
    }

    url.searchParams.delete("no_universal_links");
    url.hash = fragmentAfterLogin;
    window.history.replaceState(null, "", url.href);
}

export async function loadApp(urlParams: URLParams, matrixChatRef: React.Ref<MatrixChat>): Promise<ReactElement> {
    const config = await verifyServerConfig();
    const defaultDeviceName =
        snakedConfig.get("default_device_display_name") ?? platform?.getDefaultDeviceDisplayName();

    return (
        <wrapperOpts.Wrapper>
            <StrictMode>
                <MatrixChat
                    ref={matrixChatRef}
                    onNewScreen={onNewScreen}
                    config={config}
                    urlParams={urlParams}
                    enableGuest={!config.disable_guests}
                    onTokenLoginCompleted={onTokenLoginCompleted}
                    initialScreenAfterLogin={initialScreenAfterLogin}
                    defaultDeviceDisplayName={defaultDeviceName}
                />
            </StrictMode>
        </wrapperOpts.Wrapper>
    );
}
