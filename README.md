# Misetanibox Mobile

Android-клиент Misetanibox на ядре [mihomo](https://github.com/MetaCubeX/mihomo).
Десктопная версия (Windows/Linux) живёт отдельно: [misetanibox](https://github.com/rakexzp/misetanibox).

## Из чего собран

- **`core/`** — Go-обёртка над mihomo, собирается в `mihomo.aar` через `gomobile bind`.
- **`android/`** — нативная часть (Capacitor): VpnService, плагин-мост, плитка в шторке, виджет, автозапуск.
- **`www/`** — интерфейс (обычный HTML/JS, без фреймворка).

## Сборка

APK собирается в CI по тегу `vX.Y.Z` (`.github/workflows/android.yml`):
`gomobile bind` → `cap sync` → `gradlew assembleRelease` → подписанный APK.

**Важно:** ядро обязано собираться с `-tags with_gvisor`. Без этого тега sing-tun
подставляет заглушку, TUN не поднимается и трафик молча уходит в никуда.

Сборка подписывается ключом из GitHub Secrets (`ANDROID_KEYSTORE_BASE64`,
`ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`) — тем же, что и раньше,
иначе у пользователей сломается обновление поверх установленного.

## Раздача

Готовый APK выкладывается на зеркало:
`https://files.geodema.network/misetani/Misetanibox_android.apk`

## Благодарности

Плитка в шторке, виджет и автозапуск — вклад [@14Unight](https://github.com/14Unight).

## Лицензия

MIT. Ядро — [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) (GPL-3.0).
