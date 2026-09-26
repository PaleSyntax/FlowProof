# AGENTS.md — правила автономной реализации FlowProof

## Миссия

FlowProof — слой business outcome assurance для n8n и других workflow-движков.

Ключевая граница:

- n8n отвечает: **выполнился ли execution технически?**
- FlowProof отвечает: **случился ли правильный бизнес-результат?**

## Приоритеты

1. Correctness
2. Reproducibility
3. Evidence
4. Security
5. Simplicity
6. UX
7. Optional AI

## Основные правила

- Сначала делай working vertical slice.
- Нельзя считать README доказательством реализации.
- Нельзя использовать LLM для определения факта нарушения инварианта.
- Каждый incident обязан иметь machine-readable evidence.
- Каждый side effect обязан иметь idempotency key.
- Recovery не должен повторять весь workflow по умолчанию.
- Recovery требует human approval.
- Ошибки внешнего verifier не должны повреждать timeline.
- Не сохраняй secrets или неограниченные raw payloads.
- Не добавляй абстракции без второго реального use case.
- Не создавай собственный n8n editor/control plane.
- Не маскируй недоделанные функции mock-данными в production path.
- Demo mode должен быть явно отделён.

## Стиль кода

- Небольшие модули.
- Typed domain models.
- Dependency injection для clock, external verifier и recovery executor.
- Business logic не должна находиться в HTTP handlers или React components.
- State transitions централизованы и протестированы.
- Public API versioned under `/api/v1`.
- Timestamps — UTC, timezone-aware.
- IDs — UUID, если нет сильной причины иначе.
- JSON schemas и OpenAPI соответствуют реальному API.

## Обязательные тесты

- idempotent event ingestion;
- idempotency conflict;
- exactly_once;
- eventually до и после deadline;
- ordering;
- value mismatch;
- external false-200;
- incident deduplication;
- incident resolution;
- recovery approval gate;
- recovery idempotency;
- malformed policy;
- redaction;
- workflow JSON structure.

## Git

- Небольшие логические commits.
- Не коммить `.env`, databases, node_modules, build outputs.
- Не force-push.
- Перед push запускай проверки.
- Если remote auth недоступен, продолжай локально и документируй.

## Документация

Каждое существенное ограничение отражается в:

- `docs/IMPLEMENTATION_STATUS.md`
- `docs/KNOWN_LIMITATIONS.md`

Не заявляй то, что не доказано тестом или demo.
