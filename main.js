const NodeRSA = require('node-rsa');
const path = require('path');
const prompt = require('prompt-sync')();
const fs = require('node:fs');
const crypto = require('crypto');   
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const socketIo = require('socket.io');
const { Client, Intents } = require('discord.js');
const http = require('http');


class discordUser {
    discordUserID
    publicKey
    publicKeyPlainText

    constructor(userID, inputKey){
        this.discordUserID = userID;
        this.publicKey = new NodeRSA(inputKey);
        this.publicKeyPlainText = inputKey;
    }
    encryptMessage(message){
        return this.publicKey.encrypt(message, 'base64');
    }
}

class discordEncryption {
    privateKeysDirectory = "privateKeys"
    publicKeysDirectory = "publicKeys"
    privateKeyFilename = "encryptedPrivateKey.aes"
    publicKeyFilename = "publicKey.aes"
    privateKeyHasLoaded = false
    #key

    generateRSAkey(){
        this.#key = new NodeRSA({b: 2400});
    }
    exportPublicKey(){
        return this.#key.exportKey('pkcs8-public-pem');
    }

    savePublicKey() {
        if (!fs.existsSync(this.publicKeysDirectory)){
            fs.mkdirSync(this.publicKeysDirectory);
        }
        fs.writeFileSync(path.join(this.publicKeysDirectory, this.publicKeyFilename), this.exportPublicKey());
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
            if (!fs.existsSync(this.privateKeysDirectory)){
                fs.mkdirSync(this.privateKeysDirectory);
            }
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
            this.privateKeyHasLoaded = true;
            if (decryptedPrivateKey.slice(0, 31) != "-----BEGIN RSA PRIVATE KEY-----")
            {
                console.error("Wrong password")
            }
            this.key = new NodeRSA(decryptedPrivateKey);
        } catch (error) {
            console.error('An error occurred during decryption:', error);
            this.privateKeyHasLoaded = false;
            return null;
        } finally {
            // Attempt to clear sensitive data from memory (note: this may not be fully effective)
            password = null;
        }
    }

    decryptMessage(message){
        try {
            return this.key.decrypt(message, 'utf8');
        }
        catch 
        {
            return null;
        }
    }
    
}



class discordServerBot {
    discordUsers = [];

    async fetchPublicKeys(url){
        const response = await fetch(url);
        const text = await response.text();
        return text;
    }
    

    async fetchUsers(links)
    {
        for (let i = 0; i < links.length; i++)
        {
            this.fetchPublicKeys(links[i]).then(data => DiscordBot.parseUsers(data))
            
        }
    }

    async parseUsers(data) {
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
                    if (next_key_line.replace(/(\r\n|\n|\r)/gm, "") == "-----END PUBLIC KEY-----")
                    {
                        console.log("Detected end of key")
                        next_key += next_key_line;
                        mode = 0;
                        let new_user_object = new discordUser(next_user, next_key);
                        if (next_user in this.discordUsers)
                        {
                            if (next_key != this.discordUsers[next_user].publicKeyPlainText)
                            {
                                console.error("ALERT: Public keys do not match somone has manipulated the public keys or you forgat to update one of your public keys, for more information: https://security.stackexchange.com/questions/113347/whats-the-actual-danger-of-public-key-spoofing")
                                
                                //Commit seppuku
                                process.exit(1);
                            }
                        }
                        this.discordUsers[next_user] = new_user_object;
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

        //TODO: FIND MISSMATCH BETWEEN MULTIPLE KEYS
        return this.discordUsers;
    }

    sendMessage(user, message)
    {
        if (user in this.discordUsers){
            let encryptMessage = this.discordUsers[user].encryptMessage(message)
            return encryptMessage
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

const app = express();
app.set("view engine", "ejs");
app.set('views', path.join(__dirname, 'front'));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}))

const server = http.createServer(app);
const io = socketIo(server);


const Discordclient = new Client({
    intents: [
        Intents.FLAGS.GUILDS,
        Intents.FLAGS.GUILD_MESSAGES,
        Intents.FLAGS.MESSAGE_CONTENT,
      ],
});


const data = [
]
current_user_to_send_message = null
current_channel_to_send_message = null



DiscordEncryption = new discordEncryption()
DiscordBot = new discordServerBot();



app.get('/', (req, res) => {
    fs.stat(path.join(DiscordEncryption.privateKeysDirectory, DiscordEncryption.privateKeyFilename), function(err, stat) {
        if (err == null) {
            if (!DiscordEncryption.privateKeyHasLoaded)
            {
                res.render('SignIn')
            }
            else
            {
                res.render('Chat', {data: data});
            }
        } 
        else
        {
            res.redirect('/configuration')
        }
        
    });
})


app.get('/configuration', (req, res) => {
    res.render('Configuration')
})

app.get('/newpassword', function (req, res) {
   res.sendFile('CreateKeys.html', {root: './front'})
})

app.post('/createkeys', function (req, res) {
    console.log("keys creating");
    password = req.body.content;
    DiscordEncryption.generateRSAkey();
    DiscordEncryption.savePrivateKey(password);
    DiscordEncryption.savePublicKey();
    console.log("keys created");
    res.redirect('/')
})

app.put('/savesettings', function (req, res) {
    //TODO:Sanatize
    links = req.body.content.split("\n")
    /*
    for (let i = 0; i < links.length; i++)
    {
        //DiscordBot.fetchPublicKeys(links[i]).then(data => DiscordBot.parseUsers(data))
        
    }
    */
    DiscordBot.fetchUsers(links)

})



app.put('/authorize', function(req, res) {
    password = req.body.content;
    DiscordEncryption.loadPrivateKey(password);
    if (DiscordEncryption.privateKeyHasLoaded)
    {
        res.render('Chat', {data: data});
    }
})

app.put('/savecurrentchannel', function (req, res){
    current_channel_to_send_message = req.body.content;
})

app.put('/sendmessage', function (req, res) {
    message = req.body.content;
    message_channel = Discordclient.channels.cache.get(current_channel_to_send_message);
    encrypted_message = DiscordBot.sendMessage(current_user_to_send_message, message);
    if (encrypted_message == null)
    {
        console.error("Error during encryption")
    }
    else
    {
        message_channel.send(encrypted_message)
    }
})

app.put('/saveuser', function (req, res) {
    current_user_to_send_message = req.body.content;
})

app.put('/setoken', function (req, res ){
    Discordclient.login(req.body.content)
})

Discordclient.on('message', message => {
    decryptedMessage = DiscordEncryption.decryptMessage(message.content)
    if (decryptedMessage != null && decryptedMessage != "")
    {
        message_data = {}
        message_data['content'] = decryptedMessage
        data.push(message_data);
        io.emit('newMessage', decryptedMessage);
    }
})

server.listen(3000, (req, res) => {
    console.log("App is running on port 3000")
})