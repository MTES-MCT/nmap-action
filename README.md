# nmap-action

Scan open ports and report results as JSON.

[![units-test](https://github.com/MTES-MCT/nmap-action/actions/workflows/test.yml/badge.svg)](https://github.com/MTES-MCT/nmap-action/actions/workflows/test.yml)

Github action that scan open ports with [nmap](https://nmap.org) and report results as JSON.

## Usage

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: "MTES-MCT/nmap-action@main"
        with:
          host: scanme.nmap.org
          args: '-T4 -F'
          output: 'scans'
```

You can choose your nmap args cli except output format.
You can choose directory output.

## Hacking

To test locally, install [act](https://github.com/nektos/act).

```shell
npm run all
act -j test
```
