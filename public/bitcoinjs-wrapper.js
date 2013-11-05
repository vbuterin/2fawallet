// These are so often used....

var h2b = Bitcoin.convert.hexToBytes,
    b2h = Bitcoin.convert.bytesToHex;

// Crypto primitives

var sha256 = Bitcoin.Crypto.SHA256;

var slowsha = function(x) {
    var orig = x.split('').map(function(c) { return c.charCodeAt(0) });
    var old_pass = orig, new_pass;
    for (var i = 0; i < 1000; i++) {
        new_pass = h2b(sha256(old_pass));
        old_pass = new_pass.concat(orig)
    }
    return b2h(new_pass);
}

var importpk = function(x) {
    return new Bitcoin.Key(x);
}

var privtopub = function(x) {
    return b2h(importpk(x).getPub());
}

var pubkey_to_address = function(x,v) {
    var hash160 = Bitcoin.Util.sha256ripe160(h2b(x))
    return Bitcoin.base58.checkEncode(hash160,v);
}
var script_to_address = function(x) { return pubkey_to_address(x,5) };

// Signs a standard input

var sign = function(tx,i,pk) {
    console.log('signing',tx,i,pk);
    var btx = Bitcoin.Transaction.deserialize(h2b(tx)),
        ipk = importpk(pk),
        ipub = ipk.getPub(),
        hash160 = Bitcoin.Util.sha256ripe160(ipub),
        script = Bitcoin.Script.createOutputScript(new Bitcoin.Address(hash160)),
        hash = btx.hashTransactionForSignature( script, i, 1),
        sig = ipk.sign(hash).concat([1]);
    btx.ins[i].script = Bitcoin.Script.createInputScript(sig,ipub);
    return b2h(btx.serialize());
}

// Signs a multisig input

var multisign = function(tx,i,script,pk) {
    console.log('signing',tx,i,script,pk);
    var scriptBytes = h2b(script),
        scriptObj = new Bitcoin.Script(scriptBytes),
        txObj = Bitcoin.Transaction.deserialize(h2b(tx)),
        hash = txObj.hashTransactionForSignature(scriptObj, i, 1),
        pkObj = importpk(pk),
        sig = b2h(pkObj.sign(hash)) + '01';
    return sig;
}

// Validates a signature for a transaction input

var validate_input = function(tx,i,script,sig,pub) {
    var txObj = Bitcoin.Transaction.deserialize(h2b(tx)),
        scriptBytes = h2b(script),
        scriptObj = new Bitcoin.Script(scriptBytes),
        hash = txObj.hashTransactionForSignature(scriptObj,i,1);
    return Bitcoin.ECDSA.verify(hash, h2b(sig),
                                      h2b(pub));
}

// Given a UTXO set as inputs, create a transaction sending the money to a 
// given destination address. Includes a change address parameter

var make_sending_transaction = function(utxo, to, value, change) {
    var sum = utxo.map(function(x) { return x.value; })
                  .reduce(function(a,b) { return a+b; },0),
        outputs = [{
            address: to,   
            value: value
        }]
    if (value < 5430) { throw new Error("Amount below dust threshold!"); }
    if (sum < value) { throw new Error("Not enough money!"); }
    if (sum-value < 10000) { throw new Error("Not enough to pay 0.0001 BTC fee!"); }

    // Split change in half by default so that the wallet has multiple UTXO at all times
    if (typeof change == "string") change = [change, change];

    var changelen = Math.min(change.length,Math.floor((sum-value-10000) / 5430));

    for (var i = 0; i < changelen; i++) {
        outputs.push({ 
            address: change[i],
            value: Math.floor((sum-value-10000)/changelen) 
        });
    }
    return new Bitcoin.Transaction({
        ins: utxo.map(function(x) { return x.output }),
        outs: outputs
    })
}

// Get sufficient unspent transaction outputs from a history set to
// spend a given amount of money

var get_enough_utxo_from_history = function(h,amount,cb) {
    var utxo = h.filter(function(x) { return !x.spend });
    var valuecompare = function(a,b) { return a.value > b.value; }
    var high = utxo.filter(function(o) { return o.value >= amount; }).sort(valuecompare);
    if (high.length > 0) return [high[0]];
    utxo.sort(valuecompare);
    var totalval = 0;
    for (var i = 0; i < utxo.length; i++) {
        totalval += utxo[i].value;
        if (totalval >= amount) return utxo.slice(0,i+1);
    }
    throw ("Not enough money to send funds including transaction fee. Have: "
                 + (totalval / 100000000) + ", needed: " + (amount / 100000000));
}

// Converts a hex script into a specialized form that can be used for
// searching for pubkeys, grabbing k and n values, etc

var opcodes = _.invert(Bitcoin.Opcode.map)

var showscript = function(scr) {
    var chunks = new Bitcoin.Script(h2b(scr)).chunks;
    return chunks.map(function(x) {
        if (typeof x == "number") return opcodes[x] ? opcodes[x].substring(3) : x;
        return b2h(x);
    });
}

// Gets all pubkeys used in a multisig script

var pubkeys_from_script = function(scr) {
    if (scr.length == 66 || scr.length == 130) return scr;
    return showscript(scr).filter(function(x) {
        return typeof x == "string" && (x.length == 66 || x.length == 130)
    });
}

// Converts internal script array representation into hex script

var rawscript = function(scr) {
    var chunks = scr.map(function(x) {
        if (Bitcoin.Opcode.map['OP_'+x]) return Bitcoin.Opcode.map['OP_'+x];
        return Crypto.util.hexToBytes(x);
    });
    return Crypto.util.bytesToHex(
        chunks.reduce(function(script,x) {
            if (typeof x == "number") script.writeOp(x);
            else if (typeof x == "object") script.writeBytes(x);
            return script;
        },new Bitcoin.Script()).buffer
    );
}

// A limited, special-purpose method for creating an extended
// transaction object sending from a known address. ETO
// creation is usually best done server-side due to the need
// to make blockchain queries to determine the input addresses
// of an arbitrary transaction

var mketo = function(tx, script) {
    var txObj = Bitcoin.Transaction.deserialize(h2b(tx));
    return {
        tx: tx,
        inputscripts: txObj.ins.map(function(x) { return script }),
        sigs: txObj.ins.map(function(x) { return [] })
    }
}

// Checks the transaction for multisig inputs with sufficient signatures
// and applies them

var process_multisignatures = function(eto) {
    var eto = _.clone(eto);
    for (var i = 0; i < eto.inputscripts.length; i++) {
        var script = eto.inputscripts[i];
        if (script.length == 66 || script.length == 130) {
            continue;
        }
        if (eto.sigs[i] === true) {
            continue;
        }
        var shownscript = showscript(script),
            k = shownscript[0],
            n = shownscript[shownscript.length-2],
            pubs = shownscript.filter(function(x) {
                return (""+x).length == 66 || (""+x).length == 130
            }),
            sigs = eto.sigs[i].filter(function(x) { return x; });
        if (sigs.length < k) {
            continue;
        }
        var script2 = [].concat.apply([0],sigs.map(function(sig) { return [sig] }))
                .concat([script]),
            raw = rawscript(script2),
            txObj = Bitcoin.Transaction.deserialize(h2b(eto.tx));
        txObj.ins[i].script = new Bitcoin.Script(h2b(raw));
        eto.tx = b2h(txObj.serialize());
        eto.sigs[i] = true;
    }
    return eto;
}

// Signs an extended transaction object with a public key

var sign_eto = function(eto,pk) {
    var eto = _.clone(eto);
    for (var i = 0; i < eto.inputscripts.length; i++) {
        var script = eto.inputscripts[i];
        if (script.length == 66 || script.length == 130) {
            eto.tx = sign(eto.tx,i,pk);
            eto.sigs[i] = true;
        }
        else {
            var pubs = pubkeys_from_script(script),
                pub = privtopub(pk),
                j = pubs.indexOf(pub);
            if (j == -1) continue;
            eto.sigs[i] = eto.sigs[i] || [];
            if (eto.sigs[i] === true) { continue; }
            eto.sigs[i][j] = multisign(eto.tx,i,eto.inputscripts[i],pk);
        }
    }
    return process_multisignatures(eto);
}

//Apply a singature to an extended transaction object. Works by attempting
//to validate the transaction against every possible index/pubkey pair, and
//substituting it in where it works. Offers synchronous and asynchronous
//functionality

var apply_sig_to_eto = function(eto,sig,cb,err) {
    var eto = _.clone(eto);
    var state = "NOSIG",
        txObj = eto.tx;

    var process_input = function(i) {
        if (i >= eto.inputscripts.length) {
            return end();
        }
        var script = eto.inputscripts[i];
        if (script.length == 66 || script.length == 130) {
            var v = validate_input(eto.tx,i,script,sig)
            if (v) {
                if (eto.sigs[i] === true) { 
                    if (state == "NOSIG") state = "EXISTSIG";
                }
                else {
                    state = "SUCCESS";
                    eto.sigs[i] = true;
                }
                var ipub = h2b(eto.inputscripts[i]);
                txObj.ins[i].script = Bitcoin.Script.createInputScript(sig,ipub);
            }
        }
        else {
            var pubs = pubkeys_from_script(script);
            for (var j = 0; j < pubs.length; j++) {
                eto.sigs[i] = eto.sigs[i] || [];
                var v = validate_input(eto.tx,i,script,sig,pubs[j]);
                if (v) {
                    if (eto.sigs[i] === true || eto.sigs[i] && eto.sigs[i][j]) {
                        if (state == "NOSIG") state = "EXISTSIG";
                    }
                    else state = "SUCCESS";
                    eto.sigs[i][j] = sig;
                }
            }
        }
        if (cb) setTimeout(_.partial(process_input,i+1),25);
        else process_input(i+1);
    }

    process_input(0);

    var end = function() {
        if (state == "NOSIG") {
            if (cb && err) return err("Signature invalid");
            else throw "Signature invalid" 
        }
        else if (state == "EXISTSIG") {
            if (cb && err) return err("Signature already applied");
            else throw "Signature already applied" 
        }
        if (cb) cb(process_multisignatures(eto));
        else return process_multisignatures(eto);
    }
}

//Given an ETO, get all signatures, including partial signatures and
//full signatures extracted from the transaction itself

var get_sigs = function(eto) {
    var sigs = [],
        txobj = Bitcoin.Transaction.deserialize(h2b(eto.tx));
    for (var i = 0; i < eto.inputscripts.length; i++) {
        if (eto.sigs[i] && eto.sigs[i] !== true) {
            sigs = sigs.concat(eto.sigs[i].filter(function(x) { return x }));
        }
        else {
            if (!txobj.ins[i].script) continue;
            var script = showscript(b2h(txobj.ins[i].script.buffer));
            sigs = sigs.concat(script.filter(function(x) {
                return (""+x).substring(0,3) == "304" && (""+x).length > 130;
            }));
        }
    }
    return sigs;
}


