// The admin console's pure builders, before any page renders: the OIDC
// upsert payload (the secret discipline — OMITTED when unchanged-and-set,
// absent-key-not-null, https refused client-side), the discovery-probe
// override (always well-formed — Task 5's deferred T5-M1 means a MALFORMED
// override body is read as "no override", so the UI must never send one),
// the profile create/edit bodies, and the user patch that can never
// degenerate into the server's 400 "nothing to update".

import { describe, expect, it } from "vitest";

import {
  buildOidcPayload,
  buildOidcTestOverride,
  buildProfilePayload,
  buildUserPatch,
  isHttpsUrl,
  redirectUriPlaceholder,
  type OidcFormFields,
  type ProfileFormFields,
} from "./admin";

const OIDC_BASE: OidcFormFields = {
  provider_type: "keycloak",
  display_name: "IdP",
  discovery_url: "https://idp.example.test/realms/main/.well-known/openid-configuration",
  client_id: "wardstone-ui",
  client_secret: "",
  redirect_uri: "https://wardstone.example.test/auth/ui/oidc/keycloak/callback",
  scopes: "openid profile email",
};

describe("isHttpsUrl", () => {
  it("accepts an https URL with an authority (the server's exact rule)", () => {
    expect(isHttpsUrl("https://wardstone.example.test/auth/ui/oidc/keycloak/callback")).toBe(true);
  });

  it("refuses http and scheme-less values, and https without a host", () => {
    expect(isHttpsUrl("http://insecure.example.test/callback")).toBe(false);
    expect(isHttpsUrl("wardstone.example.test/callback")).toBe(false);
    expect(isHttpsUrl("https://")).toBe(false);
  });
});

describe("redirectUriPlaceholder", () => {
  it("names the relay callback path for the chosen provider", () => {
    expect(redirectUriPlaceholder("azure")).toBe(
      "https://<your-host>/auth/ui/oidc/azure/callback",
    );
  });
});

describe("buildOidcPayload", () => {
  it("omits client_secret from the key set when unchanged and one is stored", () => {
    const { body, error } = buildOidcPayload(OIDC_BASE, true);
    expect(error).toBeNull();
    expect(body).toBeTruthy();
    expect("client_secret" in body!).toBe(false);
  });

  it("never sends null — an empty secret maps to the ABSENT key, not null", () => {
    const { body } = buildOidcPayload(OIDC_BASE, true);
    const wire = JSON.parse(JSON.stringify(body));
    expect(wire).not.toHaveProperty("client_secret");
  });

  it("refuses an empty secret on a FIRST configuration (the server's 400)", () => {
    const { body, error } = buildOidcPayload(OIDC_BASE, false);
    expect(body).toBeNull();
    expect(error).toBe("client_secret is required when first configuring the provider");
  });

  it("sends the typed secret verbatim on a first configuration", () => {
    const { body } = buildOidcPayload({ ...OIDC_BASE, client_secret: " s3cr3t " }, false);
    expect(body!.client_secret).toBe(" s3cr3t ");
  });

  it("sends a typed secret on an existing configuration (rotation)", () => {
    const { body } = buildOidcPayload({ ...OIDC_BASE, client_secret: "rotated" }, true);
    expect(body!.client_secret).toBe("rotated");
  });

  it("refuses a non-https redirect_uri client-side with the server's wording", () => {
    const { body, error } = buildOidcPayload(
      { ...OIDC_BASE, redirect_uri: "http://localhost/auth/ui/oidc/keycloak/callback" },
      false,
    );
    expect(body).toBeNull();
    expect(error).toBe("redirect_uri must be an https URL");
  });

  it("refuses a provider_type outside keycloak|azure|custom", () => {
    const { body, error } = buildOidcPayload(
      { ...OIDC_BASE, provider_type: "auth0" } as OidcFormFields,
      true,
    );
    expect(body).toBeNull();
    expect(error).toBe("provider_type must be one of keycloak, azure, custom");
  });

  it("passes the other fields through verbatim", () => {
    const { body } = buildOidcPayload(OIDC_BASE, true);
    expect(body!.provider_type).toBe("keycloak");
    expect(body!.display_name).toBe("IdP");
    expect(body!.discovery_url).toBe(OIDC_BASE.discovery_url);
    expect(body!.client_id).toBe("wardstone-ui");
    expect(body!.redirect_uri).toBe(OIDC_BASE.redirect_uri);
    expect(body!.scopes).toBe("openid profile email");
  });
});

describe("buildOidcTestOverride", () => {
  it("is always well-formed, and omits client_secret when none is typed", () => {
    const override = buildOidcTestOverride(OIDC_BASE);
    expect(override.provider_type).toBe("keycloak");
    expect(override.discovery_url).toBe(OIDC_BASE.discovery_url);
    expect(override.redirect_uri).toBe(OIDC_BASE.redirect_uri);
    expect("client_secret" in override).toBe(false);
  });

  it("carries a typed secret when present", () => {
    const override = buildOidcTestOverride({ ...OIDC_BASE, client_secret: "x" });
    expect(override.client_secret).toBe("x");
  });
});

const PROFILE_BASE: ProfileFormFields = {
  name: " web-server ",
  description: "Server certificates",
  key_type: "ecdsa-p256",
  key_usages: ["digital_signature", "key_encipherment"],
  eku: ["server_auth"],
  lifetime_days: "30",
  san_patterns: ["*.test", "10.0.0.0/8"],
};

describe("buildProfilePayload", () => {
  it("trims the name onto a CREATE body", () => {
    const { body, error } = buildProfilePayload(PROFILE_BASE, false);
    expect(error).toBeNull();
    expect(body!.name).toBe("web-server");
    expect(body!.key_type).toBe("ecdsa-p256");
    expect(body!.key_usages).toEqual(["digital_signature", "key_encipherment"]);
    expect(body!.eku).toEqual(["server_auth"]);
    expect(body!.lifetime_days).toBe(30);
    expect(body!.san_patterns).toEqual(["*.test", "10.0.0.0/8"]);
  });

  it("carries a name-less, always-present description on an EDIT body — the PUT persists it", () => {
    const { body, error } = buildProfilePayload(PROFILE_BASE, true);
    expect(error).toBeNull();
    expect("name" in body!).toBe(false); // The update keeps the profile's name.
    expect(body!.description).toBe("Server certificates"); // …and persists its description now.
  });

  it("sends description: null when an EDIT leaves it blank (stored as NULL server-side)", () => {
    const { body } = buildProfilePayload({ ...PROFILE_BASE, description: "  " }, true);
    expect("description" in body!).toBe(true);
    expect(body!.description).toBeNull();
  });

  it("refuses a blank name on create with the server's wording", () => {
    const { body, error } = buildProfilePayload({ ...PROFILE_BASE, name: "   " }, false);
    expect(body).toBeNull();
    expect(error).toBe("a profile name is required");
  });

  it("maps a blank description to the absent key (never phantom text)", () => {
    const { body } = buildProfilePayload({ ...PROFILE_BASE, description: "  " }, false);
    expect("description" in body!).toBe(false);
  });

  it("carries a description verbatim when typed", () => {
    const { body } = buildProfilePayload(PROFILE_BASE, false);
    expect(body!.description).toBe("Server certificates");
  });

  it("refuses a lifetime below one day or not a whole number", () => {
    for (const lifetime of ["0", "-1", "abc", "1.5"]) {
      const { body, error } = buildProfilePayload(
        { ...PROFILE_BASE, lifetime_days: lifetime },
        false,
      );
      expect(body).toBeNull();
      expect(error).toBe("a profile's lifetime must be at least one day");
    }
  });
});

describe("buildUserPatch", () => {
  const alice = { role: "admin", is_active: true };

  it("sends both fields when both change", () => {
    expect(buildUserPatch(alice, { role: "viewer", is_active: false })).toEqual({
      role: "viewer",
      is_active: false,
    });
  });

  it("sends only the role when only the role changes", () => {
    expect(buildUserPatch(alice, { role: "issuer", is_active: null })).toEqual({
      role: "issuer",
    });
  });

  it("sends only is_active a re-activation/deactivation", () => {
    expect(buildUserPatch(alice, { role: null, is_active: false })).toEqual({
      is_active: false,
    });
  });

  it("returns null when nothing changes — the PATCH body is never {}", () => {
    expect(buildUserPatch(alice, { role: "admin", is_active: true })).toBeNull();
    expect(buildUserPatch(alice, { role: null, is_active: null })).toBeNull();
  });
});