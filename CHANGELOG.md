# Changelog

## [1.1.0](https://github.com/hushboxapp/crypto-ts/compare/v1.0.1...v1.1.0) (2026-04-28)


### Features

* bump typescript from 5.9.3 to 6.0.3 ([#10](https://github.com/hushboxapp/crypto-ts/issues/10)) ([f3501f1](https://github.com/hushboxapp/crypto-ts/commit/f3501f1da86d3f4668723a3190555b04fb582955))
* **crypto:** allowlist providers on decode and zero key material ([#14](https://github.com/hushboxapp/crypto-ts/issues/14)) ([e49da3d](https://github.com/hushboxapp/crypto-ts/commit/e49da3db8d6b5f7b9c51f08e41e20ff9336ae40d))
* **crypto:** bind envelope metadata via AES-GCM AAD ([#13](https://github.com/hushboxapp/crypto-ts/issues/13)) ([15d2841](https://github.com/hushboxapp/crypto-ts/commit/15d28417041e5ffe820fd37d24e0aad2acc5641e))
* **hashing:** harden KDF defaults, format, and worker ([#12](https://github.com/hushboxapp/crypto-ts/issues/12)) ([71a3cd6](https://github.com/hushboxapp/crypto-ts/commit/71a3cd6f387a86d456066aa225600a370e129528))


### Bug Fixes

* **encoding:** chunked base64 encode and unblock DTS build ([#17](https://github.com/hushboxapp/crypto-ts/issues/17)) ([20b6c38](https://github.com/hushboxapp/crypto-ts/commit/20b6c388de71bfc25e191ccbd3d5f03af40ff294))
* **hashing:** Argon2 worker checks origin ([#11](https://github.com/hushboxapp/crypto-ts/issues/11)) ([96e7d42](https://github.com/hushboxapp/crypto-ts/commit/96e7d42a618c979286d819d153c28f523b19f794))
* **key:** skip unlocked protectors on decrypt ([#18](https://github.com/hushboxapp/crypto-ts/issues/18)) ([0dbf734](https://github.com/hushboxapp/crypto-ts/commit/0dbf7345aa6dfc891ec7adaa11ce713dd6f88881))
* Shamir validation fix & OpenSSF improvements ([#3](https://github.com/hushboxapp/crypto-ts/issues/3)) ([09db114](https://github.com/hushboxapp/crypto-ts/commit/09db114deecc4e55bb17a4ce7d05c494aa05d5ef))

## [1.0.1](https://github.com/hushboxapp/crypto-ts/compare/v1.0.0...v1.0.1) (2026-03-28)


### Bug Fixes

* dependency vulnerabilities ([c898d39](https://github.com/hushboxapp/crypto-ts/commit/c898d39540a5727ba0d9886177e16d03d657b420))
* migrate organization from vaultick to hushboxapp ([a4167fa](https://github.com/hushboxapp/crypto-ts/commit/a4167fad9b36c1a683b66e709b08e9d14d3e5bc3))
* update github actions versions ([4775744](https://github.com/hushboxapp/crypto-ts/commit/4775744b7d0612b0b765774f0f4b6b80d0ec907a))

## 1.0.0 (2026-03-01)


### Features

* Argon2 Worker Implementation ([c626c4d](https://github.com/hushboxapp/crypto-ts/commit/c626c4d5f17fe5448850180eab6b139cb2302c89))
* CI Pipeline ([e392818](https://github.com/hushboxapp/crypto-ts/commit/e3928189dadf5937af531e1feddfd4bf6eb640ee))
* Code Coverage ([13cfec0](https://github.com/hushboxapp/crypto-ts/commit/13cfec08a73ad350a2ea5fc50d0f5338e1b49df5))
* Document And Key Versioning ([79ded53](https://github.com/hushboxapp/crypto-ts/commit/79ded530db8cdc2938b1887139fb12c3c11d3ce1))
* Initial Library ([60afe44](https://github.com/hushboxapp/crypto-ts/commit/60afe44117286bedcc36d77d03b27bd08813ad02))
* Initial Vault Interface ([e3c244b](https://github.com/hushboxapp/crypto-ts/commit/e3c244b46bceb2eae0e7ee3218bc9276dc8ee562))
* Linting And Formatting ([7b5797a](https://github.com/hushboxapp/crypto-ts/commit/7b5797a6567ac5dfca6616e50c08e6b82ad082de))
* NPM Publish Pipeline ([7cc68b2](https://github.com/hushboxapp/crypto-ts/commit/7cc68b284dab4bb9c81a970a1f4c753f149699c7))
* Refactored Interface ([aa56323](https://github.com/hushboxapp/crypto-ts/commit/aa56323596db81d98629ba746a5892f21b94b617))
* Robust Error Handling ([e22df17](https://github.com/hushboxapp/crypto-ts/commit/e22df176096ecea5aefdeeb1c3a835f6bd9a4b47))
* Secure Context Verification ([89aac6e](https://github.com/hushboxapp/crypto-ts/commit/89aac6e79dc21d015252a769e437a82837f9ea7c))


### Bug Fixes

* Add Firefox And Webkit Testing ([713205d](https://github.com/hushboxapp/crypto-ts/commit/713205dc3a2cd1a7843d49e07e2f61d0028ffc3b))
* Browser Compatibility ([c4b318d](https://github.com/hushboxapp/crypto-ts/commit/c4b318d550b4830da7056e8081e665efab46d0c9))
* Remove Node v16 Support ([5cb1fac](https://github.com/hushboxapp/crypto-ts/commit/5cb1face678570384ec17f236467d9a9cd311b25))
* Remove Node v18 Support ([17e1ae5](https://github.com/hushboxapp/crypto-ts/commit/17e1ae5a9f342eddef8a95ffe9566c7323b4feba))
* Resolve Release Please Permissions ([0ed02ed](https://github.com/hushboxapp/crypto-ts/commit/0ed02ed252c8ccddb71374b4dde708dfc75e0364))
* Unused Imports ([00723a6](https://github.com/hushboxapp/crypto-ts/commit/00723a60c4cbc67f82d9a9f7bc934a4e74ba649f))
