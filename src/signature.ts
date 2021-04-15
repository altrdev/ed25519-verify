import * as ed from 'noble-ed25519';
import {SignEncoding} from "./enum";

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

    async check(encoding: SignEncoding) {
        let messageHex = Buffer.from(this.message, 'utf8').toString("hex");
        let signatureHex = (encoding === SignEncoding.Base64) ? Buffer.from(this.signature, 'base64').toString("hex") : this.signature;
        let publicKeyHex = (encoding === SignEncoding.Base64) ? Buffer.from(this.publicKey, 'base64').toString("hex") : this.publicKey;
        return await ed.verify(signatureHex,messageHex,publicKeyHex).then(this.getCheckResult,this.getCheckError);
    }

    async sign(encoding: SignEncoding) {
        if(this.privateKey === null || this.privateKey === '')
            return this.getSignError("Private key missing");

        let privateKeyHex = (encoding === SignEncoding.Base64) ? Buffer.from(this.privateKey, 'base64').toString("hex") : this.privateKey;
        let hexResult = await ed.sign(Buffer.from(this.message, 'utf8').toString("hex"), privateKeyHex).then(this.getSignResult,this.getSignError);
        return ((encoding === SignEncoding.Base64) && hexResult != null) ? Buffer.from(hexResult, 'hex').toString("base64")  : hexResult;
    }

    async getPublicKey(encoding: SignEncoding) {
        if(this.privateKey === null || this.privateKey === '')
            return this.getSignError("Private key missing");

        let privateKeyHex = (encoding === SignEncoding.Base64) ? Buffer.from(this.privateKey, 'base64').toString("hex") : this.privateKey;
        let hexResult = await ed.getPublicKey(privateKeyHex).then(this.getSignResult,this.getSignError);
        return ((encoding === SignEncoding.Base64) && hexResult != null) ? Buffer.from(hexResult, 'hex').toString("base64")  : hexResult;
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


