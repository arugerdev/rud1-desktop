# Modelos de voz

`vosk-es-small.tar.gz` — modelo Vosk `vosk-model-small-es-0.42` (Apache-2.0,
<https://alphacephei.com/vosk/models>), reempaquetado como tar.gz para
vosk-browser. Da el wake word local de RIA ("Oye, RIA") en el escritorio,
donde no existe la Web Speech API de Chrome.

No se comitea: lo descarga y verifica (SHA-256) `scripts/fetch-vosk-model.mjs`
(`npm run fetch:vosk-model`), igual que el runtime de OpenVPN. Sin el modelo,
la app funciona y el toggle de activación por voz simplemente no aparece.
