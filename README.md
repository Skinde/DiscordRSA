# Summary
Discord RSA is a tool for encrypted communication trough discord using RSA encryption.
when creating a password it creates a public key and a private key that is used for communication.
the private key is then encrypted using your user password using AES-CBC and can only be decrypted using your password.


# Installation

You should upload your public key to a site that allows raw download (like github and pastebin). Then, you can share
the links to your public keys with whover you want to talk with.

DO NOT SHARE YOUR PRIVATE KEY OR PASSWORD.

you will need to install the following libraries using

```
npm install node-rsa prompt-sync fs crypto express ejs body-parser socket.io discord.js http v8
```

Then run the program using:

```
node main.js
```

Then simply connect your browser to:

```
localhost:3000
```

You will need to invite a Discord bot to a Server. Then, in the Configuration menu set the Discord Token, and Public Keys repos links. Finally, copy and paste the Channel ID and the Name of the person you want to write to in the main menu.

Write a message with the following format:

```
"Your user": "Message"
```
