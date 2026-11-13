# cJSON benchmark

This target evaluates the real upstream cJSON library, not a reimplementation.

- Upstream project: https://github.com/DaveGamble/cJSON
- Vulnerable base: tag `v1.7.17`, commit `87d8f0961a01bf09bef98ff89bae9fdec42181ee`
- Correct fix: upstream commit `7e4d5dabe7a9b754c601f214e65b544e67ba9f59` (the one-line NULL check in `cJSON_SetValuestring`)
- Upstream CVE record: CVE-2024-31755
- Upstream license: MIT, retained in each source snapshot as `LICENSE`

`patchguard_cjson_driver.c` is a small native test driver. Its input is one line in the form `initial|replacement`; the exact replacement text `NULL` makes the driver pass a C NULL pointer to `cJSON_SetValuestring`. This reaches the real library function, where the vulnerable version calls `strlen` before validating the pointer. Ordinary and long replacement strings check that valid API behavior remains intact.

`benchmark.bundle` preserves upstream history and the five evaluator refs. `vulnerable` and `correct` are based on upstream source and the upstream fix. `incomplete`, `regression`, and `unseen` are explicit teaching variants used to exercise PatchGuard's classifications; they are not claimed to be upstream releases.
