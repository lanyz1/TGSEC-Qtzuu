// Element Web v1.12.29 (2d90d6b7) apps/web/src/vector/url_utils.ts
// Guest fragment keys are parsed from the hash, not stripped by onTokenLoginCompleted.

export function parseQsFromFragment(url: Location | URL): { location: string; params?: URLSearchParams } {
    const fragment = url.hash.substring(1);
    const [main, query] = fragment.split("?", 2);

    if (main.includes("=")) {
        return {
            location: "",
            params: new URLSearchParams(main),
        };
    }

    return {
        location: decodeURIComponent(main),
        params: query ? new URLSearchParams(query) : undefined,
    };
}

const urlParameterConfig = {
    legacy_sso: {
        keys: ["loginToken"],
        location: "query",
    },
    oauth2: {
        keys: ["code", "state"],
        location: "fragment",
    },
    threepid: {
        keys: ["client_secret", "session_id", "hs_url", "is_url", "sid"],
        location: "fragment",
    },
    defaults: {
        keys: ["defaultUsername"],
        location: "fragment",
    },
    // XXX: Fragment params seemingly relating to 3pid invites, though the code in the area doubts they are ever specified
    guest: {
        keys: ["guest_user_id", "guest_access_token"],
        location: "fragment",
    },
} as const;

export function parseAppUrl(url: Location | URL): {
    location: string;
    params: URLParams;
} {
    const queryParams = new URLSearchParams(url.search);
    const parsedFragment = parseQsFromFragment(url);

    const urlParams: Partial<URLParams> = {};

    for (const group in urlParameterConfig) {
        const groupKey = group as keyof URLParams;
        const groupConfig = urlParameterConfig[groupKey];

        const params = groupConfig.location === "fragment" ? parsedFragment.params : queryParams;
        if (!params) continue;

        const target: Record<string, string> = {};
        for (const key of groupConfig.keys) {
            const value = params.get(key);
            if (value !== null) {
                target[key] = value;
            }
        }

        if (Object.keys(target).length > 0) {
            urlParams[groupKey] = target;
        }
    }

    return { params: urlParams, location: parsedFragment.location };
}
