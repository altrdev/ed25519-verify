import * as ed from 'noble-ed25519';

class VerifyEd25519 {
    message: string;
    signature: string;
    publicKey: string;
    privateKey: string;

    constructor(message, signature, publicKey, privateKey) {
        this.message = message;
        this.signature = signature;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    async check() {
        let messageHex = Buffer.from(this.message, 'utf8').toString("hex");
        let signatureHex = Buffer.from(this.signature, 'base64').toString("hex");
        let publicKeyHex = Buffer.from(this.publicKey, 'base64').toString("hex");
        return await ed.verify(signatureHex,messageHex,publicKeyHex).then(this.getCheckResult,this.getCheckError);
    }

    async sign() {
        let privateKeyHex = Buffer.from(this.privateKey, 'base64').toString("hex");
        return await ed.sign(this.message, privateKeyHex).then(this.getSignResult,this.getSignError);
    }

    getCheckResult(value) {
        return value;
    }

    getCheckError(error) {
        console.log(error);
        return false;
    }

    getSignResult(value) {
        console.log(value);
        return value;
    }

    getSignError(error) {
        console.log(error);
        return null;
    }
}

export default VerifyEd25519;


