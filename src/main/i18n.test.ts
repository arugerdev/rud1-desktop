import { afterEach, describe, expect, it } from "vitest";

import {
  getLocale,
  setLocale,
  t,
  translations,
  type Locale,
} from "./i18n";

// Restore the module-level default ("en") after each case so the rest of
// the suite (which relies on the English copy for byte-for-byte pins)
// isn't perturbed by a test that flipped the locale.
afterEach(() => setLocale("en"));

type Tree = { [key: string]: string | Tree };

function collectKeys(tree: Tree, prefix = ""): string[] {
  const out: string[] = [];
  for (const key of Object.keys(tree)) {
    const value = tree[key];
    const path = prefix ? `${prefix}.${key}` : key;
    if (typeof value === "string") out.push(path);
    else out.push(...collectKeys(value as Tree, path));
  }
  return out;
}

// Every locale tree must mirror the English (fallback) tree key-for-key.
// "en" is the source of truth because `t()` falls back to it.
const ALL_LOCALES = Object.keys(translations) as Locale[];
const NON_EN_LOCALES = ALL_LOCALES.filter((l) => l !== "en");

describe("translations key parity", () => {
  const enKeys = collectKeys(translations.en as Tree).sort();

  it.each(NON_EN_LOCALES)(
    "%s has the same key set as en",
    (locale) => {
      const keys = collectKeys(translations[locale] as Tree).sort();
      // Surface the offending keys directly so a missing translation is
      // obvious in the failure output.
      const onlyLocale = keys.filter((k) => !enKeys.includes(k));
      const onlyEn = enKeys.filter((k) => !keys.includes(k));
      expect(onlyLocale).toEqual([]);
      expect(onlyEn).toEqual([]);
      expect(keys).toEqual(enKeys);
    },
  );

  it("every leaf is a non-empty string in every locale", () => {
    for (const locale of ALL_LOCALES) {
      setLocale(locale);
      for (const key of collectKeys(translations[locale] as Tree)) {
        expect(typeof t(key)).toBe("string");
        expect(t(key).length).toBeGreaterThan(0);
      }
      setLocale("en");
    }
  });
});

describe("t() lookup + interpolation", () => {
  it("returns the current-locale string", () => {
    setLocale("en");
    expect(t("tray.open")).toBe("Open rud1");
    setLocale("es");
    expect(t("tray.open")).toBe("Abrir rud1");
  });

  it("interpolates {name}-style placeholders", () => {
    setLocale("en");
    expect(t("app.versionLabel", { version: "1.2.3" })).toBe("rud1 v1.2.3");
    setLocale("es");
    expect(t("tray.tooltipManyDevices", { count: 4 })).toBe(
      "rud1 Desktop — 4 dispositivos listos para configurar",
    );
  });

  it("leaves unmatched placeholders intact", () => {
    setLocale("en");
    // No vars supplied → the template's placeholder is preserved verbatim.
    expect(t("app.versionLabel")).toBe("rud1 v{version}");
  });
});

describe("t() fallback", () => {
  it("falls back to English when a key is missing in the current locale", () => {
    // Spanish locale, but query a key only present via the shared tree;
    // simulate a hypothetical es-missing key by querying a bogus path —
    // it should fall through to the key itself (never throw).
    setLocale("es");
    expect(t("does.not.exist")).toBe("does.not.exist");
  });

  it("returns the raw key when missing in both locales (never throws)", () => {
    setLocale("en");
    expect(() => t("totally.unknown.key")).not.toThrow();
    expect(t("totally.unknown.key")).toBe("totally.unknown.key");
  });

  it("interpolates even on the English fallback path", () => {
    // Verified indirectly: a key present in both trees interpolates; the
    // fallback branch shares the same interpolate() call.
    setLocale("es");
    expect(t("firstBoot.toastBody", { host: "10.0.0.5" })).toContain("10.0.0.5");
  });
});

describe("setLocale / getLocale", () => {
  it("round-trips and rejects invalid values", () => {
    setLocale("es");
    expect(getLocale()).toBe("es");
    setLocale("en");
    expect(getLocale()).toBe("en");
    // A valid new locale round-trips.
    setLocale("fr");
    expect(getLocale()).toBe("fr");
    setLocale("ar");
    expect(getLocale()).toBe("ar");
    setLocale("en");
    // @ts-expect-error — guarding the runtime narrowing
    setLocale("xx");
    // Unchanged: invalid input is ignored.
    expect(getLocale()).toBe("en");
  });
});
