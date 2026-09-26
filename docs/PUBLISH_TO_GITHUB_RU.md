# Как самостоятельно опубликовать FlowProof на GitHub

Репозиторий подготовлен локально. Во время этой подготовки никто не менял на
GitHub репозиторий, pull request, tag, Release, visibility, description или
topics.

## До публикации

1. Прочитай [`RELEASE_STATUS.md`](RELEASE_STATUS.md). Нельзя превращать
   `NOT_VERIFIED` в публичное обещание.
2. Убедись, что рабочее дерево чистое, и запиши точный commit:

   ```powershell
   git status --short
   git rev-parse HEAD
   ```

3. Повтори команды из [`../README.ru.md`](../README.ru.md) на чистом clone.
4. Создай или выбери профессиональный GitHub-аккаунт/организацию, где должен
   находиться публичный репозиторий. Сохраняй историю и не используй force-push.

## Рекомендуемое оформление репозитория

- Description: `Business outcome assurance for n8n: deterministic incident evidence, human-approved recovery, and independent verification.`
- Topics: `n8n`, `workflow-automation`, `fastapi`, `react`, `docker`,
  `idempotency`, `human-in-the-loop`, `business-process`
- License: MIT

## Публикация исходников

Замени пример URL на созданный тобой репозиторий. Перед push проверь remote. Не
вставляй пароль или token в команду и тем более в файлы проекта.

```powershell
git remote -v
git remote set-url origin https://github.com/OWNER/FlowProof.git
git push -u origin codex/showable-niche-product
```

Создай pull request в `main`. Принимай его только после того, как все обязательные
GitHub Actions реально выполнят шаги и пройдут на точном head. Запуск, который
закончился до выполнения шагов, имеет статус `UNKNOWN`, а не PASS. После этого
смерджи без переписывания истории и обнови локальный `main`.

```powershell
git switch main
git pull --ff-only
git rev-parse HEAD
```

## Tag и Release

Только когда проверенный commit уже находится в `main`:

```powershell
git tag -a v0.6.0 -m "FlowProof v0.6.0"
git push origin v0.6.0
```

Создай draft GitHub Release из этого tag. Прикладывай только артефакты, собранные
и проверенные из tagged commit:

- автоматически созданный GitHub source archive;
- `FlowProof-Windows-x86_64-0.6.0.zip`, только если локальный статус говорит PASS;
- `FlowProof-Windows-x86_64-0.6.0.zip.sha256`;
- очищенный machine-readable qualification evidence без секретов.

Скачай каждый загруженный asset обратно и сравни SHA-256 с опубликованным
checksum. Уже опубликованный tag нельзя передвигать: исправление выпускается как
`v0.6.1`.

## Финальная публичная проверка

Используй браузер без авторизации или новую папку без сохранённых credentials:

```powershell
git clone https://github.com/OWNER/FlowProof.git FlowProof-public-check
Set-Location FlowProof-public-check
git checkout v0.6.0
```

Проверь отображение README, ссылки и screenshots, воспроизводимость quick start и
отсутствие приватного remote или локальных путей в публичных утверждениях.
