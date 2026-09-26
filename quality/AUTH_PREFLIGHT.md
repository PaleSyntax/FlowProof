# GitHub authentication preflight

## Known

Historical note: the connected integration could access the private v0.5.0 baseline.

## Not guaranteed

A Codex terminal may use:

- separate Git credential helper;
- separate GitHub App;
- fresh container;
- different OAuth session.

## Expected

If the same authorization used for SupportFlow is account-wide and can access all repositories, a new device code is normally not required.

If the app is limited to selected repositories, FlowProof may need to be added.

## Safe check

```bash
git ls-remote https://github.com/OWNER/FlowProof.git
```

An empty repo may return no refs but exit successfully.

If available:

```bash
gh auth status
```

## Failure policy

- do not ask for a PAT;
- do not paste credentials;
- continue locally;
- make local commits;
- create `PUSH_REQUIRED.md`.

This prevents an auth prompt from wasting the session.
