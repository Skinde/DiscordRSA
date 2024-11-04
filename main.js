const NodeRSA = require('node-rsa');
const path = require('path');
const prompt = require('prompt-sync')();
const fs = require('node:fs');
const crypto = require('crypto');

filename = "encryptedPrivateKey.aes"
saltRounds = 10

function generateRSAkey(){
    return new NodeRSA({b: 2400});
}

function exportPublicKey(key){
    return key.exportKey('pkcs8-public-pem');
}

function savePrivateKey(filename, key, password) {
    try {
        // Derive key using PBKDF2 with a secure iteration count and length
        const iterations = 100000;
        const salt = crypto.randomBytes(16);  // Use a random salt
        const derivedKey = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha512');
        
        // Export and convert private key to bytes
        const decryptedPrivateKey = Buffer.from(key.exportKey('pkcs1-private'), 'utf-8');
        
        // Initialize AES encryption in CBC mode with a random IV
        const iv = crypto.randomBytes(16);  // Initialization vector for CBC mode
        const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);
        
        // Encrypt private key
        let encryptedPrivateKey = Buffer.concat([cipher.update(decryptedPrivateKey), cipher.final()]);

        // Combine salt, iv, and encrypted key for storage
        const outputBuffer = Buffer.concat([salt, iv, encryptedPrivateKey]);

        // Write the encrypted key to a file
        fs.writeFileSync(path.join("privateKeys", filename), outputBuffer);
    } catch (error) {
        console.error('An error occurred:', error);
    } finally {
        // Attempt to clear sensitive data from memory (note: this may not be fully effective)
        password = null;
    }
}

function importPublicKey(publicKey){
    return new NodeRSA(publicKey);
}

function loadPrivateKey(filename, password) {
    try {
        // Read the encrypted file
        var encryptedData = fs.readFileSync(path.join("privateKeys", filename));
        
        // Extract the salt (first 16 bytes), IV (next 16 bytes), and encrypted private key
        const salt = encryptedData.slice(0, 16);
        const iv = encryptedData.slice(16, 32);
        const encryptedPrivateKey = encryptedData.slice(32);
     
        // Derive the decryption key using the same PBKDF2 parameters
        const iterations = 100000;
        const derivedKey = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha512');

        // Initialize AES decryption in CBC mode with derived key and IV
        const decipher = crypto.createDecipheriv('aes-256-cbc', derivedKey, iv);

        // Decrypt the private key
        let decryptedPrivateKey = Buffer.concat([decipher.update(encryptedPrivateKey), decipher.final()]);

        // Convert decrypted private key back to a string if needed
        decryptedPrivateKey = decryptedPrivateKey.toString('utf-8');
        if (decryptedPrivateKey.slice(0, 31) != "-----BEGIN RSA PRIVATE KEY-----")
        {
            console.error("Wrong password")
        }
        return decryptedPrivateKey;
    } catch (error) {
        console.error('An error occurred during decryption:', error);
        return null;
    } finally {
        // Attempt to clear sensitive data from memory (note: this may not be fully effective)
        password = null;
    }
}

function encryptMessage(key, message){
    return key.encrypt(message, 'base64');
}

function decryptMessage(key, message){
    return key.decrypt(message, 'utf8');
}

function fetchfromurl(url)
{
    response = fetch(url).text();
    return response
}

key = generateRSAkey()
password = prompt("password: ");
savePrivateKey(filename, key, password);
pk = loadPrivateKey(filename, "hellofromtheotherside");


console.log(pk)