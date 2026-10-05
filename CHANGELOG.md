# Changelog

버전은 [SemVer](https://semver.org/lang/ko/)를 따릅니다 — 기능 추가는 가운데 자리(1.1.0), 버그 수정만 있으면 끝자리(1.0.1).

## [Unreleased]

## [1.0.0] — 2026-10-05

실험(1~8)과 정확도 채점까지 끝낸 상태를 첫 정식 버전으로 묶었습니다.

### Added
- MIT LICENSE (`pyproject.toml`에도 표기). 이전에는 라이선스가 없어 공개 레포여도 다른 사람이 쓸 수 없었습니다.
- `--metrics-host` 옵션, `--version`.
- 테스트 3개: `/metrics` 기본 바인딩, HTML의 LLM 판정 이스케이프, 버전 일치.
- README 영어 요약, CHANGELOG.

### Changed
- `--follow --metrics-port`의 `/metrics`가 `0.0.0.0` 대신 기본 `127.0.0.1`에서 열립니다. 다른 호스트의 Prometheus가 긁어 가야 하면 `--metrics-host 0.0.0.0`.
- CI: `actions/checkout` v5, `setup-python` v6 (Node 20 런타임 폐기 경고), main push와 PR에서만 실행 (PR마다 두 번 돌던 것).

### Fixed
- HTML 리포트에서 LLM 판정·신뢰도가 이스케이프되지 않던 부분.

## 0.1.0 — 2026-09-23 ~ 09-24

분석기 프로토타입, Falco/Tetragon·kind·lima VM·로그 회전·자동 장애 주입 실험, 손으로 매긴 35개 구간 채점, LLM 판단 실험.

[Unreleased]: https://github.com/cynkai/ebpf-observability-gap/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/cynkai/ebpf-observability-gap/releases/tag/v1.0.0
