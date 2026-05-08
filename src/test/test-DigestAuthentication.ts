import './include/common';
// eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-explicit-any
const DigestAuthentication: any = require('../DigestAuthentication.js');

// Results of this tests originally obtained from RFC 2617 and:
// 'https://pernau.at/kd/sipdigest.php'

describe('DigestAuthentication', () => {
	test('parse no auth testrealm@host.com -RFC 2617-', () => {
		const method = 'GET';
		const ruri = '/dir/index.html';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'Mufasa',
			password: 'Circle Of Life',
			realm: 'testrealm@host.com',
			ha1: null,
		};
		const challenge = {
			algorithm: 'MD5',
			realm: 'testrealm@host.com',
			nonce: 'dcd98b7102dd2f0e8b11d0f600bfb0c093',
			opaque: '5ccc069c403ebaf9f0171e9517f40e41',
			stale: null,
			qop: 'auth',
		};

		const digest = new DigestAuthentication(credentials);

		digest.authenticate({ method, ruri }, challenge, cnonce);

		expect(digest._response).toBe('6629fae49393a05397450978507c4ef1');
	});

	test('digest authenticate qop = null', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const credentials = {
			username: 'testuser',
			password: 'testpassword',
			realm: 'testrealm@host.com',
			ha1: null,
		};
		const challenge = {
			algorithm: 'MD5',
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
			qop: null,
		};

		const digest = new DigestAuthentication(credentials);

		digest.authenticate({ method, ruri }, challenge);

		expect(digest._response).toBe('f99e05f591f147facbc94ff23b4b1dee');
	});

	test('digest authenticate qop = auth', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'testuser',
			password: 'testpassword',
			realm: 'testrealm@host.com',
			ha1: null,
		};
		const challenge = {
			algorithm: 'MD5',
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
			qop: 'auth',
		};

		const digest = new DigestAuthentication(credentials);

		digest.authenticate({ method, ruri }, challenge, cnonce);

		expect(digest._response).toBe('a69b9c2ea0dea1437a21df6ddc9b05e4');
	});

	test('digest authenticate qop = auth-int and empty body', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'testuser',
			password: 'testpassword',
			realm: 'testrealm@host.com',
			ha1: null,
		};
		const challenge = {
			algorithm: 'MD5',
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
			qop: 'auth-int',
		};

		const digest = new DigestAuthentication(credentials);

		digest.authenticate({ method, ruri }, challenge, cnonce);

		expect(digest._response).toBe('82b3cab8b1c4df404434db6a0581650c');
	});

	test('digest authenticate qop = auth-int and non-empty body', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const body = 'TEST BODY';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'testuser',
			password: 'testpassword',
			realm: 'testrealm@host.com',
			ha1: null,
		};
		const challenge = {
			algorithm: 'MD5',
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
			qop: 'auth-int',
		};

		const digest = new DigestAuthentication(credentials);

		digest.authenticate({ method, ruri, body }, challenge, cnonce);

		expect(digest._response).toBe('7bf0e9de3fbb5da121974509d617f532');
	});

	test('digest authenticate with SHA-256 -RFC 7616-', () => {
		// Based on the values from example https://datatracker.ietf.org/doc/html/rfc7616#section-3.9.1

		const method = 'GET';
		const ruri = '/dir/index.html';
		const cnonce = 'f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ';
		const credentials = {
			username: 'Mufasa',
			password: 'Circle of Life',
			realm: 'http-auth@example.org',
			ha1: null,
		};
		const challenge = {
			algorithm: 'SHA-256',
			realm: 'http-auth@example.org',
			nonce: '7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v',
			opaque: 'FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS',
			stale: null,
			qop: 'auth',
		};

		const digest = new DigestAuthentication(credentials);

		digest.authenticate({ method, ruri }, challenge, cnonce);

		expect(digest._response).toBe(
			'753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1'
		);
	});

	test('digest authenticate with SHA-512-256, Charset, and Userhash -RFC 7616-', () => {
		// Based on the values from example https://datatracker.ietf.org/doc/html/rfc7616#section-3.9.2

		const method = 'GET';
		const ruri = '/doe.json';
		const cnonce = 'NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v';
		const credentials = {
			username: 'J\u00E4s\u00F8n Doe',
			password: 'Secret, or not?',
			realm: 'api@example.org',
			ha1: null,
		};
		const challenge = {
			algorithm: 'SHA-512-256',
			realm: 'api@example.org',
			nonce: '5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK',
			opaque: 'HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS',
			stale: null,
			qop: 'auth',
			userhash: true,
			charset: 'UTF-8',
		};

		const digest = new DigestAuthentication(credentials);

		digest.authenticate({ method, ruri }, challenge, cnonce);

		const authorization = digest.toString();

		// extract the hashed username parameter from the generated 'Authorization' header
		const regExResult = /username="([0-9a-fA-F]*)"/.exec(authorization ?? '');
		let usernameHash: string | undefined = 'invalid';

		if (regExResult && regExResult.length > 1) {
			usernameHash = regExResult[1];
		}

		// check if the generated 'Authorization' header contains a userhash parameter with value 'true'
		const userhash = /userhash=true/.test(authorization);

		// These are not the original hash values from example https://datatracker.ietf.org/doc/html/rfc7616#section-3.9.2,
		// but from erratum 4897 https://www.rfc-editor.org/errata/eid4897, which correctly points out that
		// the hashes in the original example were calculated with an early draft standard implementation of
		// SHA-512-256, which gives different results than the finalized standard.
		expect(digest._response).toBe(
			'3798d4131c277846293534c3edc11bd8a5e4cdcbff78b05db9d95eeb1cec68a5'
		);
		expect(usernameHash).toBe(
			'793263caabb707a56211940d90411ea4a575adeccb7e360aeb624ed06ece9b0b'
		);
		expect(userhash).toBe(true);
	});

	test('digest authenticate qop = auth and algorithm = SHA-256', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'testuser',
			password: 'testpassword',
			realm: 'testrealm@host.com',
			ha1: null,
		};
		const challenge = {
			algorithm: 'SHA-256',
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
			qop: 'auth',
		};

		const digest = new DigestAuthentication(credentials);

		digest.authenticate({ method, ruri }, challenge, cnonce);

		// calculated manually using http://emn178.github.io/online-tools/sha256.html
		expect(digest._response).toBe(
			'dccff9158e4ae98e393289e185045a6ed99b4aaee610cbe0ed73ad64b1ce86fb'
		);
	});

	test('digest authenticate qop = auth and algorithm = SHA-256-SESS', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'testuser',
			password: 'testpassword',
			realm: 'testrealm@host.com',
			ha1: null,
		};
		const challenge = {
			algorithm: 'SHA-256-SESS',
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
			qop: 'auth',
		};

		const digest = new DigestAuthentication(credentials);

		digest.authenticate({ method, ruri }, challenge, cnonce);

		// calculated manually using http://emn178.github.io/online-tools/sha256.html
		expect(digest._ha1).toBe(
			'a4767e15743db0c523c7125d9a3e944c0d315b30fe5c22ba599c8041ce947ecf'
		);
		expect(digest._response).toBe(
			'69ab2b84fd74d13e7651ba2de802490ca3f9c1d940df150dfb0e57e7a3fc787f'
		);
	});

	test('digest authenticate qop = auth and algorithm = SHA-512-256', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const cnonce = 'NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v';
		const credentials = {
			username: 'Jason Doe',
			password: 'Secret, or not?',
			realm: 'testrealm@host.com',
			ha1: null,
		};
		const challenge = {
			algorithm: 'SHA-512-256',
			realm: 'testrealm@host.com',
			nonce: '5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK',
			opaque: 'HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS',
			stale: null,
			qop: 'auth',
		};

		const digest = new DigestAuthentication(credentials);

		digest.authenticate({ method, ruri }, challenge, cnonce);

		// calculated manually using http://emn178.github.io/online-tools/sha512_256.html
		expect(digest._response).toBe(
			'3a9447d97abbaa1ecb0b0b2715fc7430b7c610a9953b67057dbe9bb6400c611b'
		);
	});

	test('digest authenticate qop = auth and algorithm = SHA-512-256-SESS', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'testuser',
			password: 'testpassword',
			realm: 'testrealm@host.com',
			ha1: null,
		};
		const challenge = {
			algorithm: 'SHA-512-256-SESS',
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
			qop: 'auth',
		};

		const digest = new DigestAuthentication(credentials);

		digest.authenticate({ method, ruri }, challenge, cnonce);

		// calculated manually using https://emn178.github.io/online-tools/sha512_256.html
		expect(digest._ha1).toBe(
			'b04a436d1b3fdf1cf7d079d5adab243ce697ed49cd3ef499b884880719eaf2f5'
		);
		expect(digest._response).toBe(
			'896624eac5d5022eae449f98bc19d85cb9c0c74cb04ec940c2a098935c9e92f4'
		);
	});

	test('digest authenticate qop = auth-int, empty body and algorithm = SHA-256', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'testuser',
			password: 'testpassword',
			realm: 'testrealm@host.com',
			ha1: null,
		};
		const challenge = {
			algorithm: 'SHA-256',
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
			qop: 'auth-int',
		};

		const digest = new DigestAuthentication(credentials);

		digest.authenticate({ method, ruri }, challenge, cnonce);

		// calculated manually using http://emn178.github.io/online-tools/sha256.html
		expect(digest._response).toBe(
			'0ace4c65bebcb70bb1afd97713d1aab441369881d94812514d7f05f07f72b442'
		);
	});

	test('digest authenticate qop = auth-int, non-empty body and algorithm = SHA-256', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const body = 'TEST BODY';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'testuser',
			password: 'testpassword',
			realm: 'testrealm@host.com',
			ha1: null,
		};
		const challenge = {
			algorithm: 'SHA-256',
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
			qop: 'auth-int',
		};

		const digest = new DigestAuthentication(credentials);

		digest.authenticate({ method, ruri, body }, challenge, cnonce);

		// calculated manually using http://emn178.github.io/online-tools/sha256.html
		expect(digest._response).toBe(
			'4ba607066f2ea1a8cd3f9402d35c7be94b7406ac6cf6068eee497d615c95737e'
		);
	});

	test('digest authenticate qop = auth-int, empty body and algorithm = SHA-512-256', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'testuser',
			password: 'testpassword',
			realm: 'testrealm@host.com',
			ha1: null,
		};
		const challenge = {
			algorithm: 'SHA-512-256',
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
			qop: 'auth-int',
		};

		const digest = new DigestAuthentication(credentials);

		digest.authenticate({ method, ruri }, challenge, cnonce);

		// calculated manually using http://emn178.github.io/online-tools/sha256.html
		expect(digest._response).toBe(
			'4dd0a3006ac4caac16b4b92304ded30fac6e0e42eb6b8fca9a8e0aaead56176c'
		);
	});

	test('digest authenticate qop = auth-int, non-empty body and algorithm = SHA-512-256', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const body = 'TEST BODY';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'testuser',
			password: 'testpassword',
			realm: 'testrealm@host.com',
			ha1: null,
		};
		const challenge = {
			algorithm: 'SHA-512-256',
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
			qop: 'auth-int',
		};

		const digest = new DigestAuthentication(credentials);

		digest.authenticate({ method, ruri, body }, challenge, cnonce);

		// calculated manually using http://emn178.github.io/online-tools/sha256.html
		expect(digest._response).toBe(
			'10800ab7a3ab2d9376b1fa15a2c54418f7f20869963edff1cd21a7807f51c859'
		);
	});

	test('digest authenticate success with algorithm = MD5 and missing qop', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'testuser',
			password: 'testpassword',
			realm: 'testrealm@host.com',
			ha1: null,
		};
		const challenge = {
			algorithm: 'MD5',
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
		};

		const digest = new DigestAuthentication(credentials);

		const success = digest.authenticate({ method, ruri }, challenge, cnonce);

		expect(success).toBe(true);
	});

	test('digest authenticate success with missing algorithm and missing qop', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'testuser',
			password: 'testpassword',
			realm: 'testrealm@host.com',
			ha1: null,
		};
		const challenge = {
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
		};

		const digest = new DigestAuthentication(credentials);

		const success = digest.authenticate({ method, ruri }, challenge, cnonce);

		expect(success).toBe(true);
	});

	test('digest authenticate failure with charset != UTF-8', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'testuser',
			password: 'testpassword',
			realm: 'testrealm@host.com',
			ha1: null,
		};
		const challenge = {
			algorithm: 'SHA-256',
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
			qop: 'auth',
			charset: 'UTF-16',
		};

		const digest = new DigestAuthentication(credentials);

		const success = digest.authenticate({ method, ruri }, challenge, cnonce);

		expect(success).toBe(false);
	});

	test('digest authenticate failure with unsupported algorithm', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'testuser',
			password: 'testpassword',
			realm: 'testrealm@host.com',
			ha1: null,
		};
		const challenge = {
			algorithm: 'SHA-384',
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
			qop: 'auth',
		};

		const digest = new DigestAuthentication(credentials);

		const success = digest.authenticate({ method, ruri }, challenge, cnonce);

		expect(success).toBe(false);
	});

	test('digest authenticate with preconfigured MD5 ha1 instead of password', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'testuser',
			password: null,
			realm: 'testrealm@host.com',
			ha1: '7b33ddc76839924578513358674924f8', // calculated manually using https://emn178.github.io/online-tools/md5.html
		};
		const challenge = {
			algorithm: 'MD5',
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
			qop: 'auth-int',
		};

		const digest = new DigestAuthentication(credentials);

		const success = digest.authenticate({ method, ruri }, challenge, cnonce);

		expect(success).toBe(true);
		// calculated manually using https://emn178.github.io/online-tools/md5.html
		expect(digest._response).toBe('82b3cab8b1c4df404434db6a0581650c');
	});

	test('digest authenticate with preconfigured SHA-256 ha1 instead of password', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'testuser',
			password: null,
			realm: 'testrealm@host.com',
			ha1: 'cd32861acd6663d1cf8dcd38862a460d5f0dc815a4372bb14cb39c3e0063b3b6', // calculated manually using https://emn178.github.io/online-tools/sha256.html
		};
		const challenge = {
			algorithm: 'SHA-256',
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
			qop: 'auth-int',
		};

		const digest = new DigestAuthentication(credentials);

		const success = digest.authenticate({ method, ruri }, challenge, cnonce);

		expect(success).toBe(true);
		// calculated manually using https://emn178.github.io/online-tools/sha256.html
		expect(digest._response).toBe(
			'0ace4c65bebcb70bb1afd97713d1aab441369881d94812514d7f05f07f72b442'
		);
	});

	test('digest authenticate failure with preconfigured MD5 ha1 instead of password, but missing realm', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'testuser',
			password: null,
			realm: null,
			ha1: '7b33ddc76839924578513358674924f8',
		};
		const challenge = {
			algorithm: 'MD5',
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
			qop: 'auth-int',
		};

		const digest = new DigestAuthentication(credentials);

		const success = digest.authenticate({ method, ruri }, challenge, cnonce);

		expect(success).toBe(false);
	});

	test('digest authenticate with replacing MD5 ha1 from previous authentication with SHA-256 ha1 after server switches algorithms', () => {
		const method = 'REGISTER';
		const ruri = 'sip:testrealm@host.com';
		const cnonce = '0a4f113b';
		const credentials = {
			username: 'testuser',
			password: 'testpassword',
			realm: 'testrealm@host.com',
			ha1: '7b33ddc76839924578513358674924f8', // the MD5 ha1 from previous authenticate() call
			digestAlgorithm: 'MD5', // the saved algorithm descriptor from previous authenticate() call
		};
		const challenge = {
			algorithm: 'SHA-256', // server switched algorithm from MD5 to SHA-256
			realm: 'testrealm@host.com',
			nonce: '5a071f75353f667787615249c62dcc7b15a4828f',
			opaque: null,
			stale: null,
			qop: 'auth-int',
		};

		const digest = new DigestAuthentication(credentials);

		const success = digest.authenticate({ method, ruri }, challenge, cnonce);

		expect(success).toBe(true);
		expect(digest._ha1).toBe(
			'cd32861acd6663d1cf8dcd38862a460d5f0dc815a4372bb14cb39c3e0063b3b6'
		);
		expect(digest._response).toBe(
			'0ace4c65bebcb70bb1afd97713d1aab441369881d94812514d7f05f07f72b442'
		);
	});
});
