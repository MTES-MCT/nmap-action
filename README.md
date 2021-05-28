# nmap-action

Scan open ports with vulnerabilities and report results as JSON.

[![units-test](https://github.com/MTES-MCT/nmap-action/actions/workflows/test.yml/badge.svg)](https://github.com/MTES-MCT/nmap-action/actions/workflows/test.yml)

Github action that scan open ports with [nmap](https://nmap.org) and its [vulners script](https://nmap.org/nsedoc/scripts/vulners.html) and report results as JSON.

## Usage

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: "MTES-MCT/nmap-action@main"
        with:
          host: scanme.nmap.org
          outputDir: 'scans'
          outputFile: 'nmapvuln.json'
          raw: false
          withVulnerabilities: true
```

You can choose your withVulnerabilities or not.
You can choose directory output and file name.

See [action.yml](action.yml) for details and default inputs.

## Hacking

To test locally, install [act](https://github.com/nektos/act).

```shell
npm run all
act -j units
```
