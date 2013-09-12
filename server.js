var sx              = require('node-sx'),
    eto             = sx.eto,
    Db              = require('mongodb').Db,
    Connection      = require('mongodb').Connection,
    Server          = require('mongodb').Server,
    BSON            = require('mongodb').BSON,
    ObjectID        = require('mongodb').ObjectID,
    express         = require('express'),
    Bitcoin         = require('bitcoinjs-lib'),
    crypto          = require('crypto'),
    base32          = require('thirty-two'),
    notp            = require('notp'),
    async           = require('async'),
    _               = require('underscore'),
    sha256          = function(x) {
                          return crypto.createHash('sha256').update(x).digest('hex') 
                      },
    slowsha         = function(x,rounds) {
                          var old_pass = x, new_pass;
                          for (var i = 0; i < (rounds || 1000); i++) {
                              new_pass = sha256(old_pass);
                              old_pass = new_pass + x;
                          }
                          return new_pass;
                      },
    eh              = sx.eh;

var host = process.env['MONGO_NODE_DRIVER_HOST'] != null 
        ? process.env['MONGO_NODE_DRIVER_HOST'] 
        : 'localhost';
var port = process.env['MONGO_NODE_DRIVER_PORT'] != null 
        ? process.env['MONGO_NODE_DRIVER_PORT'] 
        : Connection.DEFAULT_PORT;

var db = new Db('2fawal', new Server(host, port), {safe: false}, {auto_reconnect: true}, {});

var mkrespcb = function(res,code,success) {
    return eh(function(msg) { res.json(msg,code) },success);
}

var Twofactor,
    Config, 
    config,
    entropy;

db.open(function(err,dbb) {
    if (err) { throw err; }
    db = dbb;
    db.collection('config',function(err,collection) { 
        if (err) { throw err; }
        Config = collection;
        Config.findOne({},function(err,cf) {
            if (err) { throw err; }
            config = cf || {};
        });
    });
    db.collection('twofactor',function(err,collection) { 
        if (err) { throw err; }
        Twofactor = collection;
    });
});

crypto.randomBytes(100,function(err,buf) {
    if (err) { throw err; }
    entropy = buf.toString('hex');
});

var random = function(modulus) {
    var alphabet = '0123456789abcdef';
    return sha256(entropy+new Date().getTime()+Math.random()).split('')
           .reduce(function(tot,x) {
                return (tot * 16 + alphabet.indexOf(x)) % modulus;
           },0);
}

var app = express();

app.configure(function(){                                                                 
     app.set('views',__dirname + '/views');                                                  
     app.set('view engine', 'jade'); app.set('view options', { layout: false });             
     app.use(express.bodyParser());                                                          
     app.use(express.methodOverride());                                                      
     app.use(app.router);                                                                    
     app.use(express.static(__dirname + '/public'));                                         
});

var smartParse = function(x) {
    return (typeof x == "string") ? JSON.parse(x) : x;
}

app.use('/acctexists',function(req,res) {
    Twofactor.findOne({name: req.param('name')},mkrespcb(res,400,function(acct) {
        res.json(acct ? true : false);
    }));
});

app.use('/push',function(req,res) {
    console.log('pushing',req.param('tx'));
    sx.bci_pushtx(req.param('tx'),mkrespcb(res,400,_.bind(res.json,res)));
});

app.use('/history',function(req,res) {
    console.log('grabbing',req.param('address'));
    sx.history(req.param('address'),mkrespcb(res,400,function(h) {
        console.log('grabbed');
        if (req.param('unspent')) {
            h = h.filter(function(x) { return !x.spend });
        }
        if (req.param('confirmations')) {
            h = h.filter(function(x) { return x.confirmations >= parseInt(req.param('confirmations')) });
        }
        return res.json(h);
    }));
});

var b32_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

var genkey = function() {
    return _.range(16).map(function() {
        return b32_alphabet[random(32)];
    }).join('');
}

var verifykey = function(otp,key) {
    binkey = base32.decode(key)
                   .split('')
                   .map(function(x) { return x.charCodeAt(0) });
    // Check against previous, current and next TOTP key
    return notp.totp.verify(otp,binkey,{ window: 1 }); 
}

app.use('/changesecret',function(req,res) {
    var timestamp = req.param("timestamp"),
        sig = req.param("sig"),
        name = req.param("name"),
        oldkey = req.param("oldkey"),
        newkey = req.param("newkey");

    if (Math.abs(parseInt(timestamp) - new Date().getTime() / 1000) > 30) {
        return res.json("Invalid timestamp",400);
    }
    Twofactor.findOne({ name: name },eh(cb,function(tf) {
        var v = [0,1,2].map(function(i) {
            return Bitcoin.ECDSA.Verify(sha256(timestamp+newkey),sig,tf.addrdata.pubs[i])
        });
        if (!v[0] && !v[1] && !v[2]) return res.json("Invalid signature",400);
        if (oldkey != tf.key) return res.json("Incorrect auth secret",400);
        var updatedict = tf;
        delete updatedict._id;
        updatedict.key = newkey;
        Twofactor.update({ name: name },updatedict,mkrespcb(res,400,_.bind(res.json,res)));
    }));
});

app.use('/register',function(req,res) {
    console.log('Attempting registration or login');
    var name = req.param('name'),
        pub = req.param('pub'),
        bkpub = req.param('bkpub'),
        k = parseInt(req.param("k") || 2),
        pubs = [config.pub,pub,bkpub];
    async.series({
        twofactor: function(cb) { Twofactor.findOne({ name: name},cb) },
        addrdata: _.partial(sx.gen_multisig_addr_data,pubs,k)
    },mkrespcb(res,400,function(r) {
        if (r.twofactor && r.twofactor.verified) {
            // Check the given public key against the public key we remember
            // This is obviously spoofable, but the spoofer will not actually
            // gain access to the account because the private key needed for
            // the client to sign transactions is generated from the username
            // and password client side.
            if (r.twofactor.addrdata.pubs.indexOf(pub) == -1) {
                return res.json("Account exists, incorrect password",400);
            }
            return res.json({
                verified: true,
                name: name,
                addrdata: r.twofactor.addrdata
            });
        }
        else {
            var key = genkey();
            var insert = function(d,cb) { 
                // Users are required to 2FA-verify their accounts before
                // they can use them. If an account is not 2FA-verified,
                // it can be overwritten.
                if (r.twofactor) Twofactor.update({ name: name },d,cb); 
                else Twofactor.insert(d,cb);
            }
            var obj = {
                name: name,
                key: key,
                verified: false,
                addrdata: r.addrdata
            };
            insert(obj,mkrespcb(res,400,function() {
                console.log(r.twofactor ? 'Rewritten account' : 'New account',obj);
                res.json(obj);
            }));
        }
    }));
});

app.use('/validate',function(req,res) {
    var name = req.param("name"),
        otp = req.param("otp");
    Twofactor.findOne({ name: name },mkrespcb(res,400,function(tf) {
        if (!tf) {
            return res.json("Account not found",400);
        }
        if (!verifykey(otp,tf.key)) {
            return res.json("Verification failed",400);
        }
        tf.verified = true;
        Twofactor.update({ name: name },tf,mkrespcb(res,400,function(a) {
            res.json("Verification successful");
        }));
    }));
});

app.use('/admin',function(req,res) {
    var pw = req.param('pw'),
        priv = req.param('priv'),
        read = req.param('read');
    if (!pw) {
        return res.json("No password provided",403);
    }
    if (slowsha(pw,10000) != 'd82477f0daac66f152012dd14d63000d5cd63eb4ad9f7e760e492e3cf49be7d4') {
        return res.json("Bad password",403);
    }
    if (read) {
        Config.findOne({},mkrespcb(res,400,_.bind(res.json,res)));
    }
    sx.gen_addr_data(priv,mkrespcb(res,400,function(addrdata) {
        config.priv = addrdata.priv;
        config.pub = addrdata.pub;
        Config.findOne({},mkrespcb(res,400,function(c) {
            var cb = mkrespcb(res,400,_.bind(res.json,res));
            if (!c) { Config.insert(config,cb) }
            else { 
                Config.update({},config,cb);
            }
        }));
    }));
});

app.use('/2fasign',function(req,res) {
    var name = req.param("name"),
        otp = req.param("otp"),
        tx = req.param("tx"),
        eto_object = req.param("eto");
    Twofactor.findOne({ name: name },mkrespcb(res,400,function(tf) {
        if (!tf) { 
            res.json("Name not found",400);
        }
        else if (!verifykey(otp,tf.key)) {
            res.json("Verification failed",400);
        }
        else {
            async.waterfall([function(cb) {
                if (eto_object) {
                    if (typeof eto_object == "string") {
                        try {
                            eto_object = JSON.parse(eto_object);
                        }
                        catch(e) { return cb(e); }
                    }
                    cb(null,eto_object);
                }
                else {
                    var sm = {}
                    sm[tf.addrdata.address] = tf.addrdata.raw;
                    eto.mketo(tx,sm,null,cb);
                }
            },function(eto_object,cb) {
                eto.signeto(eto_object,config.priv,cb);
            }],mkrespcb(res,400,_.bind(res.json,res)));
        }
    }));
});

app.use('/',function(req,res) {                                                           
    res.render('2fawallet.jade',{});                                                           
});

app.listen(3191);

return app;
