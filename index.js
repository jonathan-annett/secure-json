module.exports = function (withKeys){
  
    const crypto = require("crypto");
    const fs = require ('fs');
    const zlib=require('zlib');
    const toZlibB64 = (x)=>zlib.deflateSync(Buffer.from(x,'utf8'),{level:9,memLevel:9}).toString('base64').replace(/\=/g,'');
    const fromZlibB64 = (x) => zlib.inflateSync(Buffer.from(x,'base64')).toString('utf8');

    //keys will live in here
    const keys = {};

    // generate 64 bytes of base64(ish) chars (eg no / or +)
    let passphrase = newPassPhrase();

    // generate text exported keys
    let exportedKeys = withKeys ? {} : crypto.generateKeyPairSync("rsa", {
      // The standard secure default length for RSA keys is 2048 bits
      modulusLength: 2048,
       'publicKeyEncoding': {
                'type': 'spki',
                'format': 'pem',
            },
            'privateKeyEncoding': {
                'type': 'pkcs8',
                'format': 'pem',
                'cipher': 'aes-256-cbc',
                'passphrase': passphrase
            }
    });

    // define some importers (they basically decompress b64 encoded strings and create keys from that)
    const importKeys = {
        publicKey : function(b64) {
           keys.publicKey = crypto.createPublicKey({
                'key': fromZlibB64(b64),
                'format': 'pem',
                'type': 'spki',
            });
        },
        privateKey : function(b64,passphrase) {
          keys.privateKey = crypto.createPrivateKey({
              'key': fromZlibB64(b64),
              'format': 'pem',
              'type': 'pkcs8',
              'cipher': 'aes-256-cbc',
              'passphrase': passphrase
          });
        },
        keys : function(b64) {
          try {
              const args = JSON.parse(fromZlibB64(b64));
              if (Array.isArray(args) && args.length===3) {
                keys.publicKey = crypto.createPublicKey({
                      'key': args[0], 
                      'format': 'pem',
                      'type': 'spki',
                });
                passphrase = args[2];
                keys.privateKey = crypto.createPrivateKey({
                    'key':args[1], 
                    'format': 'pem',
                    'type': 'pkcs8',
                    'cipher': 'aes-256-cbc',
                    'passphrase': passphrase
                });   
                return true;
              }
              return false;

          } catch (ouch) {
            return false;
          }

        }
    };
  
    const self =  {
      stringify : toJSON,
      parse: fromJSON,
      importKeys,
      setKeyPair,
      exportedKeys,
      lockdown
    };
  
  
    if (withKeys) {
      if (importKeys.keys(withKeys)) {
         lockdown();
      } else {
         return null;
      }
    } else {

      // create keys ready to use
      // this function also replaces the text versions of the exported keys with base64 deflated versions, ready for export
      setKeyPair( toZlibB64(exportedKeys.publicKey), toZlibB64(exportedKeys.privateKey), passphrase);
    }
    
    return self;
  

    function newPassPhrase(){
       const buf = Buffer.alloc(256);
       return crypto.randomFillSync(buf).toString('base64').replace(/\/|\+|=/g,'').substr(-64);
    }

    function setKeyPair(pub, priv, pass) {
      importKeys.publicKey(pub);
      importKeys.privateKey(priv,pass);

      exportedKeys.publicKey=pub;
      exportedKeys.privateKey=priv;
      exportedKeys.passphrase = pass;
      exportedKeys.keys = toZlibB64(JSON.stringify([fromZlibB64(pub),fromZlibB64(priv),passphrase]));
    }

    function toJSON(obj, replacer) {
      const insecure = zlib.deflateSync(Buffer.from(JSON.stringify(obj,replacer)),{level:9,memLevel:9});
      const encryptedData = crypto.publicEncrypt(
        {
          key: keys.publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256"
        },
        insecure
      );
      return '["'+encryptedData.toString("base64").replace(/\=/g,'')+'"]';
    }

    function fromJSON(json) {
      try {
        const payload = JSON.parse(json);
        if (Array.isArray(payload) && payload.length===1) {
          const encryptedData = Buffer.from(payload[0], "base64");
          const decryptedData = crypto.privateDecrypt(
            {
              key: keys.privateKey,
              padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
              oaepHash: "sha256"
            },
            encryptedData
          );
          return JSON.parse(zlib.inflateSync(decryptedData));
        }
      } catch (ouch) {
        return null;
      }
    }

    // prevent access or changes to the keys
    // used once configuration is loaded.
    function lockdown() {
      delete exportedKeys.keys;
      delete exportedKeys.passphrase;
      delete exportedKeys.privateKey;
      delete self.exportedKeys;
      delete self.importKeys;
      delete self.setKeyPair; 
      delete self.lockdown;
      passphrase = undefined;
    }


}
