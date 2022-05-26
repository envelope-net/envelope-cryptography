using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Envelope.Cryptography.PGP;

public partial class PGPProvider : IPGPEncrypt, IPGPEncryptAndSign, IPGPSign, IPGPClearSign, IPGPDecrypt, IPGPDecryptAndVerify, IPGPGetRecipients, IPGPGenerateKey
{
	/// <inheritdoc />
	public void GenerateKey(
		string publicKeyFilePath,
		string privateKeyFilePath,
		string? username = null,
		string? password = null,
		int strength = 1024,
		int certainty = 8,
		bool emitVersion = true)
	{
		if (string.IsNullOrEmpty(publicKeyFilePath))
			throw new ArgumentNullException(nameof(publicKeyFilePath));

		if (string.IsNullOrEmpty(privateKeyFilePath))
			throw new ArgumentNullException(nameof(privateKeyFilePath));

		using var pubs = File.Open(publicKeyFilePath, FileMode.Create);
		using var pris = File.Open(privateKeyFilePath, FileMode.Create);
		GenerateKey(pubs, pris, username, password, strength, certainty, emitVersion: emitVersion);
	}

	/// <inheritdoc />
	public void GenerateKey(
		Stream publicKeyStream,
		Stream privateKeyStream,
		string? username = null,
		string? password = null,
		int strength = 1024,
		int certainty = 8,
		bool armor = true,
		bool emitVersion = true)
	{
		username ??= string.Empty;
		password ??= string.Empty;

		var kpg = new RsaKeyPairGenerator();
		kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), new SecureRandom(), strength, certainty));
		var kp = kpg.GenerateKeyPair();

		if (privateKeyStream == null)
			throw new ArgumentNullException(nameof(privateKeyStream));

		if (publicKeyStream == null)
			throw new ArgumentNullException(nameof(publicKeyStream));

		ArmoredOutputStream? secretOutArmored;
		if (armor)
		{
			secretOutArmored = new ArmoredOutputStream(privateKeyStream);
			if (!emitVersion)
			{
				secretOutArmored.SetHeader(ArmoredOutputStream.HeaderVersion, null);
			}
			privateKeyStream = secretOutArmored;
		}
		else
		{
			secretOutArmored = null;
		}

		var secretKey = new PgpSecretKey(
			_options.PgpSignatureType,
			_options.PublicKeyAlgorithm,
			kp.Public,
			kp.Private,
			DateTime.UtcNow,
			username,
			_options.SymmetricKeyAlgorithm,
			password.ToCharArray(),
			null,
			null,
			new SecureRandom()
			//                ,"BC"
			);

		secretKey.Encode(privateKeyStream);

		secretOutArmored?.Dispose();

		ArmoredOutputStream? publicOutArmored;
		if (armor)
		{
			publicOutArmored = new ArmoredOutputStream(publicKeyStream);
			if (!emitVersion)
			{
				publicOutArmored.SetHeader(ArmoredOutputStream.HeaderVersion, null);
			}
			publicKeyStream = publicOutArmored;
		}
		else
		{
			publicOutArmored = null;
		}

		var key = secretKey.PublicKey;

		key.Encode(publicKeyStream);

		publicOutArmored?.Dispose();
	}
}
