//const ed25519 = require('ed25519-supercop');
import * as ed from 'noble-ed25519';

class VerifyEd25519 {
    message: string;
    signature: string;
    publicKey: string;

    constructor(message, signature, publicKey) {
        this.message = message;
        this.signature = signature;
        this.publicKey = publicKey;
    }

    async check() {
        let messageBuffer = Buffer.from(this.message, 'utf8').toString("hex");
        let signatureBuffer = Buffer.from(this.signature, 'base64').toString("hex");
        let publicKeyBuffer = Buffer.from(this.publicKey, 'base64').toString("hex");
        return await ed.verify(signatureBuffer,messageBuffer,publicKeyBuffer).then(this.getResult,this.getError);
    }

    getResult(value) {
        return value;
    }

    getError(error) {
        console.log(error);
        return false;
    }
}

export default VerifyEd25519;


