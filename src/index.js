const core = require('@actions/core');
const exec = require('@actions/exec');
const parse = require('./parser');
const fs = require("fs");

function getFilename(outputFile){
  const oFileA = outputFile.split('.');
  const filename = oFileA && oFileA.length == 2 ? oFileA[0] : 'nmapvuln';
  return filename;
}

async function run() {
  try {
    const workspace = process.env.GITHUB_WORKSPACE;
    const image = core.getInput('image');
    const host = core.getInput('host');
    const outputDir = core.getInput('outputDir');
    const outputFile = core.getInput('outputFile');
    const raw = core.getInput('raw');
    const withVulnerabilities = core.getInput('withVulnerabilities');
    const path = workspace + '/' + outputDir;
    await exec.exec(`mkdir -p ${path}`);
    await exec.exec(`docker pull ${image} -q`);
    const filename = getFilename(outputFile);
    const nmap = (`docker run --user 0:0 -v ${path}:/data --network="host" -t ${image} ${filename} ${host} ${withVulnerabilities}`);
    try {
      await exec.exec(nmap);
      const data = await parse(path, `${filename}.xml`, raw == 'true', withVulnerabilities == 'true');
      fs.writeFileSync(`${outputDir}/${outputFile}`, JSON.stringify(data));
    } catch (error) {
      core.setFailed(error.message);
    }
  } catch (error) {
    core.setFailed(error.message);
  }
}

run();