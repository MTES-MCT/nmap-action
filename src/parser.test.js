const parse = require("./parser");


describe("parse html report to json", () => {
  
  test("nmapvuln.xml raw should return raw json", async () => {
    const data = await parse(process.cwd()+'/src', 'nmapvuln.xml', true, true);
    expect(data).not.toBeNull();
    expect(data.nmaprun.scaninfo[0].$.protocol).toEqual("tcp");
    expect(data.nmaprun.host[0].hostnames[0].hostname[0].$.name).toEqual("scanme.nmap.org");
    expect(data.nmaprun.host[0].ports[0].extraports[0].$.state).toEqual("closed");
    expect(data.nmaprun.host[0].ports[0].extraports[0].$.count).toEqual("993");
    expect(data.nmaprun.host[0].ports[0].port.length).toEqual(7);
    expect(data.nmaprun.host[0].ports[0].port[0].service[0].$.name).toEqual("ssh");
    expect(data.nmaprun.host[0].ports[0].port[0].service[0].$.version).toEqual("6.6.1p1 Ubuntu 2ubuntu2.13");
    expect(data.nmaprun.host[0].ports[0].port[0].script[0].table[0].table.length).toEqual(3);
    expect(data.nmaprun.host[0].ports[0].port[0].script[0].table[0].table[0].elem.length).toEqual(4);
    expect(data.nmaprun.host[0].ports[0].port[0].script[0].table[0].table[0].elem[0].$.key).toEqual("is_exploit");
    expect(data.nmaprun.host[0].ports[0].port[0].script[0].table[0].table[0].elem[0]._).toEqual("false");
    expect(data.nmaprun.host[0].ports[0].port[0].script[0].table[0].table[0].elem[1].$.key).toEqual("cvss");
    expect(data.nmaprun.host[0].ports[0].port[0].script[0].table[0].table[0].elem[1]._).toEqual("8.5");
    expect(data.nmaprun.host[0].ports[0].port[0].script[0].table[0].table[0].elem[2].$.key).toEqual("id");
    expect(data.nmaprun.host[0].ports[0].port[0].script[0].table[0].table[0].elem[2]._).toEqual("CVE-2015-5600");
  });

  test("nmapvuln.xml not raw should return transformed json", async () => {
    const data = await parse(process.cwd()+'/src', 'nmapvuln.xml', false, true);
    expect(data).not.toBeNull();
    expect(data.protocol).toEqual("tcp");
    expect(data.host).toEqual("scanme.nmap.org");
    expect(data.closed_ports).toEqual("993");
    expect(data.open_ports.length).toEqual(7);
    expect(data.open_ports[0].service.name).toEqual("ssh");
    expect(data.open_ports[0].service.version).toEqual("6.6.1p1 Ubuntu 2ubuntu2.13");
    expect(data.open_ports[0].service.vulnerabilities.length).toEqual(3);
    expect(data.open_ports[0].service.vulnerabilities[0].is_exploit).toEqual("false");
    expect(data.open_ports[0].service.vulnerabilities[0].cvss).toEqual("8.5");
    expect(data.open_ports[0].service.vulnerabilities[0].id).toEqual("CVE-2015-5600");
  });

  test("openports.xml raw should return raw json", async () => {
    const data = await parse(process.cwd()+'/src', 'openports.xml', true, false);
    expect(data).not.toBeNull();
    expect(data.nmaprun.scaninfo[0].$.protocol).toEqual("tcp");
    expect(data.nmaprun.host[0].hostnames[0].hostname[0].$.name).toEqual("scanme.nmap.org");
    expect(data.nmaprun.host[0].ports[0].extraports[0].$.state).toEqual("closed");
    expect(data.nmaprun.host[0].ports[0].extraports[0].$.count).toEqual("95");
    expect(data.nmaprun.host[0].ports[0].port.length).toEqual(5);
    expect(data.nmaprun.host[0].ports[0].port[0].service[0].$.name).toEqual("ssh");
  });

  test("openports.xml not raw should return transformed json", async () => {
    const data = await parse(process.cwd()+'/src', 'openports.xml', false, false);
    expect(data).not.toBeNull();
    expect(data.protocol).toEqual("tcp");
    expect(data.host).toEqual("scanme.nmap.org");
    expect(data.closed_ports).toEqual("95");
    expect(data.open_ports.length).toEqual(5);
    expect(data.open_ports[0].service.name).toEqual("ssh");
  });

});
