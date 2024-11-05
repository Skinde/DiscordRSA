const NodeRSA = require('node-rsa');
const path = require('path');
const prompt = require('prompt-sync')();
const fs = require('node:fs');
const crypto = require('crypto');   
const express = require('express');
const discordjs = require('discord.js')

class discordUser {
    discordUserID
    publicKey

    constructor(userID, inputKey){
        this.discordUserID = userID;
        this.publicKey = new NodeRSA(inputKey);
    }
    encryptMessage(message){
        return this.publicKey.encrypt(message, 'base64');
    }
}

class discordEncryption {
    privateKeyFilename = "encryptedPrivateKey.aes"
    publicKeyFilename = "publicKey.aes"
    #key

    generateRSAkey(){
        this.#key = new NodeRSA({b: 2400});
    }
    exportPublicKey(){
        return this.#key.exportKey('pkcs8-public-pem');
    }

    savePublicKey() {
        fs.writeFileSync(path.join("publicKeys", this.publicKeyFilename), this.exportPublicKey());
    }

    savePrivateKey(password) {
        try {
            // Derive key using PBKDF2 with a secure iteration count and length
            const iterations = 100000;
            const salt = crypto.randomBytes(16);  // Use a random salt
            const derivedKey = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha512');
            
            // Export and convert private key to bytes
            const decryptedPrivateKey = Buffer.from(this.#key.exportKey('pkcs1-private'), 'utf-8');
            
            // Initialize AES encryption in CBC mode with a random IV
            const iv = crypto.randomBytes(16);  // Initialization vector for CBC mode
            const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);
            
            // Encrypt private key
            let encryptedPrivateKey = Buffer.concat([cipher.update(decryptedPrivateKey), cipher.final()]);
    
            // Combine salt, iv, and encrypted key for storage
            const outputBuffer = Buffer.concat([salt, iv, encryptedPrivateKey]);
    
            // Write the encrypted key to a file
            fs.writeFileSync(path.join("privateKeys", this.privateKeyFilename), outputBuffer);
        } catch (error) {
            console.error('An error occurred:', error);
        } finally {
            // Attempt to clear sensitive data from memory (note: this may not be fully effective)
            password = null;
        }
    }

    loadPrivateKey(password) {
        try {
            // Read the encrypted file
            var encryptedData = fs.readFileSync(path.join("privateKeys", this.privateKeyFilename));
            
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
            this.key = new NodeRSA(decryptedPrivateKey);
        } catch (error) {
            console.error('An error occurred during decryption:', error);
            return null;
        } finally {
            // Attempt to clear sensitive data from memory (note: this may not be fully effective)
            password = null;
        }
    }

    decryptMessage(message){
        return this.key.decrypt(message, 'utf8');
    }
    
}



class discordServerBot {
    discordUsers = [];

    async fetchPublicKeys(url){
        const response = await fetch(url);
        const text = await response.text();
        return text;
    }
    
    parseUsers(data) {
        let mode = 0;
        let next_user = "";
        let next_key = "";
        let next_key_line = "";
        
        for (let i = 0; i < data.length; i += 1) {

            // Mode 0 parses the users
            if (mode == 0)
            {
                next_user += data[i];

                if (data[i] == ':'){
                    next_user = next_user.substring(0,next_user.length - 1); //eat :
                    mode = 1;
                    i += 1; //eat \n
                }
            }

            // Mode 1 parses the public keys
            else
            {
                next_key_line += data[i];
                if (data[i] == '\n')
                {
                    // Create new user object and pass the userid and userkey data
                    if (next_key_line == "-----END PUBLIC KEY-----\n")
                    {
                        next_key += next_key_line;
                        mode = 0;
                        let new_user_object = new discordUser(next_user, next_key);
                        this.discordUsers.push(new_user_object);
                        next_user = "";
                        next_key_line = "";
                        next_key = "";
                    }

                    // Else add the next line to the key
                    else
                    {
                        next_key += next_key_line;
                        next_key_line = "";
                    }
                }
                
            }
        }
        return this.discordUsers;
    }

    sendMessage(user, message)
    {
        for (let i = 0; i < this.discordUsers.length; i++)
        {
            if (this.discordUsers[i].discordUserID == user) {
                let encryptMessage = this.discordUsers[i].encryptMessage(message)
                return encryptMessage
            }
        }
        console.error("User not found");
        return null;
        
    }

    async loadAndParseUsers(url) {
        try {
            const text = await this.fetchPublicKeys(url);
            const users = await this.parseUsers(text);
            this.discordUsers = users; // Store the parsed users in the bot instance
        } catch (error) {
            console.error("Error loading or parsing users:", error);
        }
    }
    
}

const app = express()
app.use(express.json());
const router = express.Router();
const Discordclient = new discordjs.Client();

current_user_to_send_message = null
current_channel_to_send_message = null



DiscordEncryption = new discordEncryption()
DiscordBot = new discordServerBot();
DiscordEncryption.loadPrivateKey(prompt("password: "))

app.set("view engine", "pug");
app.set("views", path.join(__dirname, "views"));


app.get('/', (req, res) => {
    res.sendFile('Chat.html',{root: "./front"})
})


app.get('/configuration', (req, res) => {
    res.sendFile('Configuration.html',{root: "./front"})
})

app.put('/savesettings', function (req, res) {
    //TODO:Sanatize
    links = req.body.content.split("\n")
    for (let i = 0; i < links.length; i++)
    {
        DiscordBot.fetchPublicKeys(links[i]).then(data => DiscordBot.parseUsers(data)).then(parseData => {console.log(DiscordBot.discordUsers)})
    }

})

app.put('/savecurrentchannel', function (req, res){
    current_channel_to_send_message = req.body.content;
})

app.put('/sendmessage', function (req, res) {
    message = req.body.content;
    console.log(DiscordBot.discordUsers);
    message_channel = Discordclient.channels.cache.get(current_channel_to_send_message);
    encrypted_message = DiscordBot.sendMessage(current_user_to_send_message, message);
    message_channel.send(encrypted_message)
})

app.put('/saveuser', function (req, res) {
    current_user_to_send_message = req.body.content;
})


Discordclient.login(prompt("token: "))
app.listen(3000)