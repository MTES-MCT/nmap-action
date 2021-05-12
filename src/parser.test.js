const parse = require("./parser");


describe("parse html report to json", () => {

  test("should return json", async () => {
    const data = await parse(process.cwd()+'/src');
    expect(data).not.toBeNull();
    expect(data.nmaprun.scaninfo[0].$.protocol).toEqual("tcp");
    expect(data.nmaprun.host[0].hostnames[0].hostname[0].$.name).toEqual("scanme.nmap.org");
    expect(data.nmaprun.host[0].ports[0].port.length).toEqual(5);
  });

});
