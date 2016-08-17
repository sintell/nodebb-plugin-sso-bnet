(function(module) {
	"use strict";

	/*
		Welcome to the SSO OAuth plugin! If you're inspecting this code, you're probably looking to
		hook up NodeBB with your existing OAuth endpoint.

		Step 1: Fill in the "constants" section below with the requisite informaton. Either the "oauth"
				or "oauth2" section needs to be filled, depending on what you set "type" to.

		Step 2: Give it a whirl. If you see the congrats message, you're doing well so far!

		Step 3: Customise the `parseUserReturn` method to normalise your user route's data return into
				a format accepted by NodeBB. Instructions are provided there. (Line 137)

		Step 4: If all goes well, you'll be able to login/register via your OAuth endpoint credentials.
	*/

	var User = module.parent.require('./user'),
		Groups = module.parent.require('./groups'),
		meta = module.parent.require('./meta'),
		db = module.parent.require('../src/database'),
		guild = module.parent.require('../src/guild/guild'),
		passport = module.parent.require('passport'),
		fs = module.parent.require('fs'),
		path = module.parent.require('path'),
		nconf = module.parent.require('nconf'),
		winston = module.parent.require('winston'),
		async = module.parent.require('async'),
		constants = Object.freeze({
			type: 'oauth2',		// Either 'oauth' or 'oauth2'
			name: 'bnet',		// Something unique to your OAuth provider in lowercase, like "github", or "nodebb"
			oauth: {
				requestTokenURL: '',
				accessTokenURL: '',
				userAuthorizationURL: '',
				consumerKey: '',
				consumerSecret: ''
			},
			oauth2: {
				authorizationURL: 'https://' + process.env.BNET_LOCATION + '.battle.net/oauth/authorize',
				tokenURL: 'https://' + process.env.BNET_LOCATION + '.battle.net/oauth/token',
				clientID: process.env.BNET_ID,
				clientSecret: process.env.BNET_SECRET
			},
			scope: 'wow.profile',
            location: process.env.BNET_LOCATION,

			// This is the address to your app's "user profile" API endpoint (expects JSON)
			userIdRoute: 'https://' + process.env.BNET_LOCATION + '.api.battle.net/account/user/id',
			userBattletagRoute: 'https://' + process.env.BNET_LOCATION + '.api.battle.net/account/user/battletag',
			userCharactersRoute: 'https://' + process.env.BNET_LOCATION + '.api.battle.net/wow/user/characters?locale=' +
                process.env.BNET_LOCALE
		}),
		configOk = false,
		OAuth = {}, passportOAuth, opts;

        process.stdout.write('===\n'+process.env.BNET_ID + '\n' + process.env.BNET_SECRET)

	if (!constants.name) {
		winston.error('[sso-oauth] Please specify a name for your OAuth provider (library.js:32)');
	} else if (!constants.type || (constants.type !== 'oauth' && constants.type !== 'oauth2')) {
		winston.error('[sso-oauth] Please specify an OAuth strategy to utilise (library.js:31)');
	} else {
		configOk = true;
	}

	OAuth.getStrategy = function(strategies, callback) {
		if (configOk) {
			passportOAuth = require('passport-oauth')[constants.type === 'oauth' ? 'OAuthStrategy' : 'OAuth2Strategy'];

			if (constants.type === 'oauth') {
				// OAuth options
				opts = constants.oauth;
				opts.callbackURL = nconf.get('url') + '/auth/' + constants.name + '/callback';

				passportOAuth.Strategy.prototype.userProfile = function(token, secret, params, done) {
					this._oauth.get(constants.userRoute, token, secret, function(err, body, res) {
						if (err) { return done(new Error('failed to fetch user profile', err)); }

						try {
							var json = JSON.parse(body);
							OAuth.parseUserReturn(json, function(err, profile) {
								if (err) return done(err);
								profile.provider = constants.name;
								done(null, profile);
							});
						} catch(e) {
							done(e);
						}
					});
				};
			} else if (constants.type === 'oauth2') {
				// OAuth 2 options
				opts = constants.oauth2;
				opts.callbackURL = nconf.get('url') + '/auth/' + constants.name + '/callback';
                var userAccessToken;
				passportOAuth.Strategy.prototype.userProfile = function(accessToken, done) {
					var _this = this;
                    userAccessToken = accessToken;
					return _this._oauth2.get(constants.userIdRoute, accessToken, function(err, body, res) {
						if (err) { return done(new Error('failed to fetch user id', err)); }

						var idJson = {};
						try {
							idJson = JSON.parse(body);
						} catch(e) {
							return done(e);
						}

						return _this._oauth2.get(constants.userBattletagRoute, accessToken, function(err, body, res) {
							if (err) { return done(new Error('failed to fetch user battletag', err)); }

							var battletagJson = {};
							try {
								battletagJson = JSON.parse(body);
							} catch(e) {
								return done(e);
							}

							return _this._oauth2.get(constants.userCharactersRoute, accessToken, function(err, body, res) {
								if (err) { return done(new Error('failed to fetch user characters', err)); }

								var charactersJson = {};
								try {
									charactersJson = JSON.parse(body);
								} catch(e) {
									return done(e);
								}

								return OAuth.parseUserReturn(idJson, battletagJson, charactersJson, function(err, profile) {
									if (err) return done(err);
									profile.provider = constants.name;
									return done(null, profile);
								});
							});
						});
					});
				};
			}

			passport.use(constants.name, new passportOAuth(opts, function(token, secret, profile, done) {
				OAuth.login({
					oAuthid: profile.id,
        			email: '',
					handle: profile.displayName,
					isAdmin: profile.isAdmin,
					isGuild: profile.isGuild,
                    availableNicknames: profile.availableNicknames,
					bnetData: {
                   	    accessToken: userAccessToken,
	                    characters: profile.characters
	                }
				}, function(err, user) {
					if (err) {
						return done(err);
					}
					done(null, user);
				});
			}));

			strategies.push({
				name: constants.name,
				url: '/auth/' + constants.name,
				callbackURL: '/auth/' + constants.name + '/callback',
				icon: 'fa-sign-in',
				scope: (constants.scope || '').split(',')
			});

			callback(null, strategies);
		} else {
			callback(new Error('OAuth Configuration is invalid'));
		}
	};

	OAuth.parseUserReturn = function(idJson, battletagJson, charactersJson, callback) {
		// Alter this section to include whatever data is necessary
		// NodeBB *requires* the following: id, displayName, emails.
		// Everything else is optional.

		// Find out what is available by uncommenting this line:
		// console.log(data);

		var profile = {};
		profile.id = idJson.id;
        guild.composeUserCharacters(charactersJson.characters, function(err, characters, nicks) {
            if (err) {
                winston.error(err);
                callback(err);
            }
            profile.characters = characters;

            if (nicks.length > 0) {
        		profile.isGuild = true;
                profile.availableNicknames = nicks;
                profile.displayName = nicks[0];
    		} else {
    		   profile.displayName = battletagJson.battletag.replace('#', '-');
    		}

    		// Do you want to automatically make somebody an admin? This line might help you do that...
    		profile.isAdmin = (profile.id == process.env.ADMIN_ID);

    		callback(null, profile);
        });
	};

	OAuth.login = function(payload, callback) {
		OAuth.getUidByOAuthid(payload.oAuthid, function(err, uid) {
			if (err) {
				return callback(err);
			}

			if (uid !== null) {
				// Existing User
                async.waterfall([
                    async.apply(User.setUserField, uid, 'bnetData', payload.bnetData),
                    function(next) {
                        User.getUserField(uid, 'username', function(err, username) {
                            // If nick is in available ones then check if it is set to main char
                            if (payload.availableNicknames.indexOf(username) !== -1) {
                                guild.setMainCharacter(uid, username, next);
                            }
                            // Else set default nick
                            User.updateProfile(uid, {username: payload.handle}, next);
                        });
                    }
                ], () => {
                    if (payload.isGuild) {
                        Groups.join('Snails', uid, function(err) {
                            callback(null, {
                                uid: uid
                            });
                        });
                    } else {
                        callback(null, {
                            uid: uid
                        });
                    }
                });
			} else {
				// New User
				var success = function(uid) {
					// Save provider-specific information to the user
					User.setUserField(uid, constants.name + 'Id', payload.oAuthid);
					db.setObjectField(constants.name + 'Id:uid', payload.oAuthid, uid);

					if (payload.isGuild) {
						Groups.join('Snails', uid, function(err) {
							if (err != null) {
								winston.error('Error joining "Snails" group for ' + payload.handle + ': ' + err);
							}
							winston.info('Invite to "Snails" for ' + payload.handle);
							callback(null, {
								uid: uid
							});
						});
					} else {
						callback(null, {
							uid: uid
						});
					}
				};

                User.create({
                    username: payload.handle,
                    bnetData: payload.bnetData,
                    email: ''
                }, function(err, uid) {
                    if(err) {
                        return callback(err);
                    }

                    success(uid);
                });
            }
		});
	};

	OAuth.getUidByOAuthid = function(oAuthid, callback) {
		db.getObjectField(constants.name + 'Id:uid', oAuthid, function(err, uid) {
			if (err) {
				return callback(err);
			}
			callback(null, uid);
		});
	};

	OAuth.deleteUserData = function(uid, callback) {
		async.waterfall([
			async.apply(User.getUserField, uid.uid, constants.name + 'Id'),
			function(oAuthIdToDelete, next) {
				db.deleteObjectField(constants.name + 'Id:uid', oAuthIdToDelete, next);
			}
		], function(err) {
			if (err) {
				winston.error('[sso-oauth] Could not remove OAuthId data for uid ' + uid + '. Error: ' + err);
				return callback(err);
			}
			callback(null, uid);
		});
	};

	module.exports = OAuth;
}(module));
