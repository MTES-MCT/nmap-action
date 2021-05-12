const core = require('@actions/core');
const exec = require('@actions/exec');
const parse = require('./parser');
const fs = require("fs");

async function run() {
  try {
    const workspace = process.env.GITHUB_WORKSPACE;
    const image = core.getInput('image');
    const host = core.getInput('host');
    const output = core.getInput('output');
    const args = core.getInput('args');

    const path = workspace + '/' + output;
    await exec.exec(`mkdir -p ${path}`);
    await exec.exec(`docker pull ${image} -q`);
    const nmap = (`docker run --user 0:0 -v ${path}:/data --network="host" -t ${image} ${args} --no-stylesheet -oX /data/report.xml ${host}`);
    try {
      await exec.exec(nmap);
      const data = await parse(path);
      fs.writeFileSync(`${output}/openports.json`, JSON.stringify(data));
    } catch (error) {
      core.setFailed(error.message);
    }
  } catch (error) {
    core.setFailed(error.message);
  }
}

run();