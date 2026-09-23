const version = "3.8.0";
const supported = new Set(["en", "es", "de", "fr", "pt-BR", "ru", "tr", "zh-Hans"]);
let translations = {};

async function readTranslations(language) {
  const response = await fetch(`/miwifi_static/translations/${language}.json?v=${version}`);
  if (!response.ok) throw new Error(`Translation request failed: ${response.status}`);
  return response.json();
}

export async function loadTranslations(hass) {
  const requested = hass.language || "en";
  const base = requested.split("-")[0];
  const language = supported.has(requested) ? requested : supported.has(base) ? base : "en";
  try {
    const english = await readTranslations("en");
    translations = english;
    if (language !== "en") {
      translations = {...english, ...await readTranslations(language)};
    }
  } catch (error) {
    console.warn("MiWiFi translations could not be fully loaded", error);
  }
}

export function localize(key) {
  return translations[key] || key;
}
