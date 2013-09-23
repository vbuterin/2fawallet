angular.module('2fawallet', []);

var el = function(x) { return document.getElementById(x); }
var qs = function(x) { return document.querySelectorAll(x); }

function TFAWalletCtrl($scope,$http) {
    window.wscope = $scope;

    $scope.user = {};
    $scope.sending = {};

    var strim = function(x) {
        if (!x) return '';
        var test = function(c) { return c == '"' || c == "'" }
        return x.substring(test(x[0]) ? 1 : 0,x.length - (test(x[x.length-1]) ? 1 : 0));
    }

    $scope.errlogger = function(r) {
         $scope.message = {
            title: "Error",
            body: r ? strim(r.data || r) : "Unknown error" 
         };
         if (!$scope.$$phase) $scope.$apply();
         throw r;
    }

    var entropy = "",
        owm = window.onmousemove;

    window.onmousemove = function(e) {
        entropy += "" + e.x + e.y + (new Date().getTime() % 1337);
        if (entropy.length > 2000) {
            window.onmousemove = owm;
        }
        if (owm) owm(e);
    }

    $scope.objdiff = function(o1, o2, key) {
        var obj = {};
        o2.map(function(o) { obj[key(o)] = true });
        return o1.filter(function(o) { return !obj[key(o)] });
    }
    $scope.txodiff = function(txo1, txo2) {
        return $scope.objdiff(txo1,txo2,function(x) { return x.output });
    }

    $scope.signrequest = function(url,req,key) {
        var keys = [];
        var smartEncode = function(x) {
            return encodeURIComponent(
                (typeof x == "string" || typeof x == "number") ? x : JSON.stringify(x)
            );
        }
        for (var v in req) keys.push(v);
        keys.sort();
        var s = keys.reduce(function(s,k) {
            return s + '?' + smartEncode(k) + '=' + smartEncode(req[k])
        },url);
        console.log('k',key,'s',s);
        var z = sha256(s);
        console.log(z);
        return b2h(new Bitcoin.ECKey(key).sign(h2b(z)));
    }

    $scope.login = function() {
        $scope.message = {
            title: "Loading",
            body: "Generating private keys",
            loading: true
        };
        if (!$scope.$$phase) { $scope.$apply(); }

        setTimeout(function(){
            // Primary private key (username+password derived)
            var seed = $scope.user.name + ":" + $scope.user.pw;
            $scope.user.priv = base58checkEncode(slowsha(seed),128);
            $scope.user.pub = privtopub($scope.user.priv);
    
            // Backup private key (randomly generated)
            var rndseed = ""+new Date().getTime()+Math.random()+entropy;
            $scope.user.bkpriv = base58checkEncode(sha256(rndseed),128);
            $scope.user.bkpub = privtopub($scope.user.bkpriv);
    
            ($scope.message || {}).body = "Registering account";
            $http.post('/register',{
                name: $scope.user.name,
                pub: $scope.user.pub,
                bkpub: $scope.user.bkpub
            })
            .then(function(resp) {
                ($scope.message || {}).body = "Processing response";
                console.log(resp.data);
                $scope.user.tfakey = resp.data.key;
                $scope.user.address = resp.data.addrdata.address;
                $scope.user.script = resp.data.addrdata.raw;
                $scope.user.pubs = resp.data.addrdata.pubs;
                if (!resp.data.verified) {
                    $scope.state = 1;
                    el("qr1").innerHTML = "";
                    new QRCode(el("qr1"),{ 
                        text: $scope.user.bkpriv,
                        width: 120,
                        height: 120
                    });
                    qs("#qr1 img")[0].style.margin = "0 auto";
                }
                else {
                    delete $scope.user.bkpriv;
                    delete $scope.user.bkpub;
                    $scope.state = 3;
                    $scope.getbalance();
                }
                $scope.message = null;
            },$scope.errlogger);
        },100);
    }
    $scope.confirmSavedBackup = function() {
        var next;
        $scope.message = {
            title: "Confirm",
            body: "Did you actually save the QR code and/or the private key? If you do not save them the data will be lost forever as soon as you close this browser session",
            actiontext: "Yes, I did, don't worry",
            action: function() { next(); }
        }
        next = function() {
            $scope.state = 2;
            new QRCode(el("qr2"),{
                text: "otpauth://totp/"+$scope.user.name+"@EgoraMultisig?secret=" + $scope.user.tfakey,
                width: 120,
                height: 120
            });
            qs("#qr2 img")[0].style.margin = "0 auto";
            $scope.message = null;
        }
    }
    $scope.confirmOTP = function(name,otp,cb) {
        return $http.post('/validate', { name: $scope.user.name, otp: $scope.otp })
            .then(function(r) {
                console.log('yay',r);
                $scope.state = 3;
                $scope.msg = { text: r.data };
                $scope.getbalance();
            },$scope.errlogger);
    }
    $scope.send = function() {
        $scope.message = {
            title: "Sending",
            body: "Generating transaction",
            loading: true
        }
        console.log('generating');
        $http.post('validate', { name: $scope.user.name, otp: $scope.sending.otp })
        .then(function() {
            console.log('validated');
            var satoshis = Math.ceil(parseFloat($scope.sending.value) * 100000000),
                fee      = 10000;
            while (1) {
                var utxo = get_enough_utxo_from_history($scope.utxo,satoshis + fee),
                    tx   = make_sending_transaction(utxo,
                                                    $scope.sending.to,
                                                    satoshis,
                                                    $scope.user.address);
                if (Math.ceil(tx.length / 2048) * 10000 > fee) {
                    fee = Math.ceil(tx.length / 2048)
                }
                else break;
            }
            $scope.eto      = mketo(tx, $scope.user.script);

            $scope.usedutxo = utxo;
            $scope.usedutxo.map(function(x) { x.timestamp = new Date().getTime() });

            console.log('e0',$scope.eto);
            ($scope.message || {}).body = "Signing transaction";
            var pubindex = $scope.user.pubs.indexOf($scope.user.pub);
            for (var i = 0; i < $scope.eto.inputscripts.length; i++) {
                $scope.eto.sigs[i][pubindex] = multisign($scope.eto.tx,
                                                         i,
                                                         $scope.eto.inputscripts[i],
                                                         $scope.user.priv);
            }
            ($scope.message || {}).body = "Sending transaction to server for second signature";
            console.log('e1',$scope.eto);
            var obj = {
                name: $scope.user.name,
                otp: $scope.sending.otp,
                eto: $scope.eto
            }
            obj.sig = $scope.signrequest('/2fasign',obj,$scope.user.priv);
            return $http.post('/2fasign',obj);
        },$scope.errlogger)
        .then(function(r) {
            ($scope.message || {}).body = "Pushing transaction";
            $scope.eto = r.data;
            console.log('e2',$scope.eto);
            return $http.post('/push',{ tx: $scope.eto.tx })
        },$scope.errlogger)
        .then(function(r) {
            console.log('Success',r.data);
            var txhash = sha256(Crypto.util.hexToBytes($scope.eto.tx));
            ($scope.message || {}).body = strim(r.data) || txhash;
            ($scope.message || {}).loading = false;
            $scope.waiting = $scope.waiting.concat($scope.usedutxo || []);
            $scope.usedutxo = [];
        },$scope.errlogger)
    }
    $scope.utxo = [];
    $scope.waiting = [];
    $scope.getbalance = function() {
        if (!$scope.user.address) { return }
        $http.post('/history', { address: $scope.user.address })
            .then(function(r) {
                $scope.history = r.data;
                var unspent = $scope.history.filter(function(x) { return !x.spend }),
                    spent = $scope.history.filter(function(x) { return x.spend }),
                    time = new Date().getTime();

                $scope.waiting = $scope.txodiff($scope.waiting,spent)
                    .filter(function(x) {
                        return !x.timestamp || time < (x.timestamp + 600000)
                    });
                $scope.utxo = $scope.txodiff(unspent,$scope.waiting);
                var satoshis = $scope.utxo.map(function(x) { return x.value; })
                                          .reduce(function(a,b) { return a+b; },0);
                var ncf_satoshis = $scope.waiting.map(function(x) { return x.value; })
                                          .reduce(function(a,b) { return a+b; },0);
                $scope.balance = Math.floor(satoshis / 1000) / 100000;
                $scope.ncf_balance = Math.floor(ncf_satoshis / 1000) / 100000;

            },function(){});
    }
    setInterval($scope.getbalance,6667);
}
