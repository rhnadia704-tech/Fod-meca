# FOD Detector

Application Android analytique et non intrusive dédiée à la détection, au traçage en temps réel, à la rétro-ingénierie et à la comparaison forensique du mécanisme **Fingerprint On Display (FOD)** entre une **Custom ROM de référence** et une **GSI** partageant le **même `boot` et le même `vendor` (non modifiés)**.

## Fonctionnalités principales

- **Diagnostic FOD (`ROM FOD` / `GSI FOD`)** :
  - Inventaire dynamique sans structure figée : HAL HIDL/AIDL (`lshal`, VINTF, `service list`), services système (`FingerprintService`, `BiometricService`, `SurfaceFlinger`), nœuds `sysfs` HBM/LHBM/DRM, propriétés système, overlays RRO, règles `init.rc`, refus SELinux et **recensement exhaustif de tous les patchs** présents.
  - Capture guidée pendant un **enregistrement réel d'empreinte** dans les Paramètres Android.
  - Tableau de bord dynamique **FOD LIVE TRACE** : `SESSION FLOW`, `COMPONENT INTELLIGENCE` (avec inspecteur ELF64/32 et désassemblage AArch64), `DEPENDENCY GRAPH` interactif, `LIVE INVESTIGATION` (`FAIT` / `CORRÉLATION` / `DÉDUCTION` / `HYPOTHÈSE`) et `DIAGNOSTIC SUMMARY`.
  - États stricts `OBSERVED`, `CONFIRMED`, `FAILED`, `SUSPECT`, `UNKNOWN` (les éléments inaccessibles ne sont jamais inventés).
  - Synthèse de rétro-ingénierie par **Firebase AI Logic** (`gemini-4-carbon`, `ThinkingLevel.HIGH`).
- **Exportation sans troncature** :
  - **Rapport local unique monolithique** (`.html` autonome ou `.md` complet) écrit en streaming pour supporter des fichiers très volumineux sans saturation mémoire.
  - **Archive ZIP complète** (inventaires, journaux bruts intégraux, désassemblage ELF, métadonnées et `report.json`).
- **Comparateur Forensique (`COMPARATEUR`)** :
  - Import de deux archives ZIP (`CUSTOM ROM` et `GSI`), vérification de parité `boot`/`vendor`, comparaison sur 8 dimensions et pistes correctives côté système (sans modification `vendor`/`boot`).
- **Paramètres (`PARAMÈTRES`)** :
  - Bilingue **Français / Anglais**, thème clair/sombre automatique, **Mode Root (`su`) facultatif en lecture seule**, et gestion stockage (**SAF** par défaut + option **Accès tous fichiers**).

## GitHub Actions CI

Le workflow `.github/workflows/android-ci.yml` exécute `:app:testDebugUnitTest` et `:app:assembleDebug` à chaque `push` et publie l'APK Debug en artefact.
