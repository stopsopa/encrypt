// Minimal ssh-agent "sign" client used as the bridged signer for the browser participant:
// the browser builds the data to sign, this forwards it to the (throwaway) test agent.
import { connect } from "node:net";

const str = (b: Uint8Array): Buffer => {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(b.length);
  return Buffer.concat([len, b]);
};

export function agentSign(publicKeyBlob: Uint8Array, data: Uint8Array): Promise<Buffer> {
  const sockPath = process.env.SSH_AUTH_SOCK;
  if (!sockPath) return Promise.reject(new Error("SSH_AUTH_SOCK is not set"));
  const keyType = Buffer.from(publicKeyBlob.subarray(4, 4 + Buffer.from(publicKeyBlob).readUInt32BE(0))).toString();
  const flags = Buffer.alloc(4);
  flags.writeUInt32BE(keyType === "ssh-rsa" ? 4 : 0);
  const body = Buffer.concat([Buffer.from([13]), str(publicKeyBlob), str(data), flags]);
  return new Promise((resolve, reject) => {
    const sock = connect(sockPath);
    let buf = Buffer.alloc(0);
    sock.on("error", reject);
    sock.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length < 4 || buf.length < 4 + buf.readUInt32BE(0)) return;
      sock.destroy();
      if (buf[4] !== 14) return reject(new Error("ssh-agent refused to sign (key not loaded?)"));
      resolve(buf.subarray(9, 9 + buf.readUInt32BE(5)));
    });
    sock.write(str(body));
  });
}
