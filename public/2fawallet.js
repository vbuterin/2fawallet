angular.module('2fawallet', []);

var el = function(x) { return document.getElementById(x); }
var qs = function(x) { return document.querySelectorAll(x); }

function TFAWalletCtrl($scope,$http) {
    window.wscope = $scope;

    $scope.user = {};
    $scope.sending = {};

    $scope.errlogger = function(r) {
         $scope.message = { title: "Error", body: r.data || r };
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
        var z = sha256(s);
        return b2h(Bitcoin.ECDSA.sign(h2b(z),new Bitcoin.ECKey(key)));
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
                text: "otpauth://totp/EgoraMultisig?secret=" + $scope.user.tfakey,
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
        $http.post('validate', { name: $scope.user.name, otp: $scope.sending.otp })
        .then(function() {
            var satoshis = Math.ceil(parseFloat($scope.sending.value) * 100000000),
                utxo     = get_enough_utxo_from_history($scope.history,satoshis + 10000),
                tx       = make_sending_transaction(utxo,
                                                    $scope.sending.to,
                                                    satoshis,
                                                    $scope.user.address),
                _        = console.log(tx),
                eto      = mketo(tx, $scope.user.script);

            console.log('e0',eto);
            ($scope.message || {}).body = "Signing transaction";
            var pubindex = $scope.user.pubs.indexOf($scope.user.pub);
            for (var i = 0; i < eto.inputscripts.length; i++) {
                eto.sigs[i][pubindex] = multisign(eto.tx,i,eto.inputscripts[i],$scope.user.priv);
            }
            ($scope.message || {}).body = "Sending transaction to server for second signature";
            console.log('e1',eto);
            var obj = {
                name: $scope.user.name,
                otp: $scope.sending.otp,
                eto: eto
            }
            obj.sig = signrequest('/2fasign',obj,$scope.user.priv);
            return $http.post('/2fasign',obj);
        },$scope.errlogger)
        .then(function(r) {
            ($scope.message || {}).body = "Pushing transaction";
            var eto = r.data;
            console.log('e2',eto);
            return $http.post('/push',{ tx: eto.tx })
        },$scope.errlogger)
        .then(function(r) {
            ($scope.message || {}).body = r.data;
            ($scope.message || {}).loading = false;
        },$scope.errlogger)
    }
    $scope.getbalance = function() {
        if (!$scope.user.address) { return }
        $http.post('/history', { address: $scope.user.address })
            .then(function(r) {
                $scope.history = r.data;
                var satoshis = $scope.history.filter(function(x) { return !x.spend })
                                             .map(function(x) { return x.value; })
                                             .reduce(function(a,b) { return a+b; },0);
                $scope.balance = Math.floor(satoshis / 1000) / 100000

            },function(){});
    }
    setInterval($scope.getbalance,6667);
}
