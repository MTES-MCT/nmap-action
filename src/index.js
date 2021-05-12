const core = require('@actions/core');
const exec = require('@actions/exec');
const parse = require('./parser');
const fs = require("fs");

async function run() {
  try {
    const workspace = process.env.GITHUB_WORKSPACE;
    const image = core.getInput('image');
    const host = core.getInput('host');
    const outputDir = core.getInput('outputDir');
    const outputFile = core.getInput('outputFile');
    const raw = core.getInput('raw');
    const withVulnerabilities = core.getInput('withVulnerabilities');
    const args = withVulnerabilities ? '-sV --script vulners --script-args mincvss=5.0' : '-T4 -F';

    const path = workspace + '/' + outputDir;
    await exec.exec(`mkdir -p ${path}`);
    await exec.exec(`docker pull ${image} -q`);
    const oFileA = outputFile.split('.');
    const xmlFile = oFileA && oFileA.length == 2 ? oFileA[0] + '.xml' : 'report';
    const nmap = (`docker run --user 0:0 -v ${path}:/data --network="host" -t ${image} ${args} --no-stylesheet -oX ${'/data/' + xmlFile} ${host}`);
    try {
      await exec.exec(nmap);
      const data = await parse(path, xmlFile, raw, withVulnerabilities);
      fs.writeFileSync(`${outputDir}/${outputFile}`, JSON.stringify(data));
    } catch (error) {
      core.setFailed(error.message);
    }
  } catch (error) {
    core.setFailed(error.message);
  }
}

run();