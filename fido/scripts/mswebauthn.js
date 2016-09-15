"use strict";

var WebAuthentication = (function () {

	const WebAuthenticationDB = (function() {
		const WebAuthentication_DB_VERSION = 1;
		const WebAuthentication_DB_NAME = "_WebAuthentication";
		const WebAuthentication_ID_TABLE = "identities";

		var db = null;
		var initPromise = null;

		function initDB() {
			return new Promise(function(resolve,reject) {
				var req = indexedDB.open(WebAuthentication_DB_NAME,WebAuthentication_DB_VERSION);
				req.onupgradeneeded = function() {
					// new database - set up store
					db = req.result;
					var store = db.createObjectStore(WebAuthentication_ID_TABLE, { keyPath: "id"});
				};
				req.onsuccess = function() {
					db = req.result;
					resolve();
				};
				req.onerror = function(e) {
					reject(e);
				};
			});
		}

		function store(id,data) {
			if(!initPromise) { initPromise = initDB(); }
			return initPromise.then(function() { doStore(id,data) });
		}

		function doStore(id,data) {
			if(!db) throw "DB not initialised";
			return new Promise(function(resolve,reject) {
				var tx = db.transaction(WebAuthentication_ID_TABLE,"readwrite");
				var store = tx.objectStore(WebAuthentication_ID_TABLE);
				store.put({id:id,data:data});
				tx.oncomplete = function() {
					resolve();
				}
				tx.onerror = function(e) {
					reject(e);
				};
			});
		}

		function getAll() {
			if(!initPromise) { initPromise = initDB(); }
			return initPromise.then(doGetAll);
		}

		function doGetAll() {
			if(!db) throw "DB not initialized";
			return new Promise(function(resolve,reject) {
				var tx = db.transaction(WebAuthentication_ID_TABLE,"readonly");
				var store = tx.objectStore(WebAuthentication_ID_TABLE);
				var req = store.openCursor();
				var res = [];
				req.onsuccess = function() {
					var cur = req.result;
					if(cur) {
						res.push({id:cur.value.id,data:cur.value.data});
						cur.continue();
					} else {
						resolve(res);
					}
				}
				req.onerror = function(e) {
					reject(e);
				};
			});
		}

		return {
			store: store,
			getAll: getAll
		};
	}());

    function makeCredential(accountInformation, cryptoParameters, attestationChallenge, options) {
		var acct = {rpDisplayName: accountInformation.rpDisplayName, userDisplayName: accountInformation.displayName};
		var params = [];
		var i;
		
		if (accountInformation.name) { acct.accountName = accountInformation.name; }
		if (accountInformation.id) { acct.userId = accountInformation.id; }
		if (accountInformation.imageUri) { acct.accountImageUri = accountInformation.imageUri; }

		for ( i = 0; i < cryptoParameters.length; i++ ) {
			if ( cryptoParameters[i].type === 'ScopedCred' ) {
				params[i] = { type: 'FIDO_2_0', algorithm: cryptoParameters[i].algorithm };
			} else {
				params[i] = cryptoParameters[i];
			}
		}
        return msCredentials.makeCredential(acct, params, attestationChallenge).then(function (cred) {
			if (cred.type === "FIDO_2_0") {
				var result = Object.freeze({
					credential: {type: "ScopedCred", id: cred.id},
					publicKey: JSON.parse(cred.publicKey),
					attestation: cred.attestation
				});
				return WebAuthenticationDB.store(result.credential.id,accountInformation).then(function() { return result; });
			} else {
				return cred;
			}
		});
    }

    function getCredList(whitelist) {
		var credList = [];
    	if(whitelist) {
    		return new Promise(function(resolve,reject) {
    			whitelist.forEach(function(item) {
					if (item.type === 'ScopedCred' ) {
						credList.push({ type: 'FIDO_2_0', id: item.id });
					} else {
						credList.push(item);
					}
    			});
    			resolve(credList);
			});
    	} else {
    		return WebAuthenticationDB.getAll().then(function(list) {
    			list.forEach(item => credList.push({ type: 'FIDO_2_0', id: item.id }));
    			return credList;
    		});
    	}
    }

    function getAssertion(assertionChallenge, options) {
		return getCredList(options.allowList).then(function(credList) {
			var filter = { accept: credList }; 
			var sigParams = undefined;
			if (credentialExtensions && credentialExtensions["WebAuthentication.txauth.simple"]) { sigParams = { userPrompt: credentialExtensions["WebAuthentication.txauth.simple"] }; }

	        return msCredentials.getAssertion(assertionChallenge, filter, sigParams).then(function (sig) {
				if (sig.type === "FIDO_2_0"){
					return Object.freeze({
						credential: {type: "ScopedCred", id: sig.id},
						clientData: sig.signature.clientData,
						authenticatorData: sig.signature.authnrData,
						signature: sig.signature.signature
					});
				} else {
					return sig;
				}
			});
		});
    }

    return {
        makeCredential: makeCredential,
        getAssertion: getAssertion
    };
})();