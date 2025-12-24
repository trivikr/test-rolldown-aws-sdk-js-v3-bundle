# test-rolldown-aws-sdk-js-v3-bundle

Repro for issue noticed in https://github.com/trivikr/find-aws-sdk-js-v2-usage/actions/runs/20020773491/job/57407001593?pr=13

## Reproduction

- Run `npm i` to install dependencies.
- Run `./test-build.sh` to run `npm run build` and fail when the generated bundle has a diff.
  - The git diff will get detected in some iteration, ranging from 1 to 10.

### Example run

```console
$ ./test-build.sh
...

---------------

Iteration 2

> build
> rolldown -c

<DIR>/bundle.js  chunk │ size: 381.24 kB

✔ rolldown v1.0.0-beta.57 Finished in 93.30 ms
No changes in bundle.js

---------------

Iteration 3

> build
> rolldown -c

<DIR>/bundle.js  chunk │ size: 381.23 kB

✔ rolldown v1.0.0-beta.57 Finished in 92.95 ms
Git diff detected in bundle.js - failing at iteration 3
```
