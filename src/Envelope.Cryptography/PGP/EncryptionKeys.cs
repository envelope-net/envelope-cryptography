using Envelope.Cryptography.PGP.Internal;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.Text;

namespace Envelope.Cryptography.PGP;

public class EncryptionKeys : IEncryptionKeys
{
	private readonly Lazy<IEnumerable<PgpPublicKey>> _publicKeys;
	private readonly Lazy<PgpPrivateKey?> _privateKey;
	private readonly Lazy<PgpSecretKey?> _secretKey;
	private readonly Lazy<PgpSecretKeyRingBundle?> _secretKeys;

	private readonly string? _passPhrase;

	public PgpPublicKey? PublicKey => PublicKeys.FirstOrDefault();
	public IEnumerable<PgpPublicKey> PublicKeys => _publicKeys.Value;
	public PgpPrivateKey? PrivateKey => _privateKey.Value;
	public PgpSecretKeyRingBundle? SecretKeys => _secretKeys.Value;
	public PgpSecretKey? SecretKey => _secretKey.Value;

	/// <summary>
	/// Initializes a new instance of the EncryptionKeys class.
	/// Two keys are required to encrypt and sign data. Your private key and the recipients public key.
	/// The data is encrypted with the recipients public key and signed with your private key.
	/// </summary>
	/// <param name="publicKey">The key used to encrypt the data</param>
	/// <param name="privateKey">The key used to sign the data.</param>
	/// <param name="passPhrase">The password required to access the private key</param>
	/// <param name="encoding"></param>
	/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
	public EncryptionKeys(string publicKey, string privateKey, string passPhrase, Encoding? encoding = null)
	{
		if (string.IsNullOrEmpty(publicKey))
			throw new ArgumentNullException(nameof(publicKey));

		if (string.IsNullOrEmpty(privateKey))
			throw new ArgumentNullException(nameof(privateKey));

		if (passPhrase == null)
			throw new ArgumentNullException(nameof(passPhrase));

		_publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
		{
			return new List<PgpPublicKey>() { Utilities.ReadPublicKey(publicKey.GetStream(encoding)) };
		});

		_secretKeys = new Lazy<PgpSecretKeyRingBundle?>(() =>
		{
			using var inputStream = PgpUtilities.GetDecoderStream(privateKey.GetStream(encoding));
			return new PgpSecretKeyRingBundle(inputStream);
		});

		_secretKey = new Lazy<PgpSecretKey?>(() =>
		{
			return ReadSecretKey();
		});

		_privateKey = new Lazy<PgpPrivateKey?>(() =>
		{
			return ReadPrivateKey(passPhrase);
		});

		_passPhrase = passPhrase;
	}

	/// <summary>
	/// Initializes a new instance of the EncryptionKeys class.
	/// Two keys are required to encrypt and sign data. Your private key and the recipients public key.
	/// The data is encrypted with the recipients public key and signed with your private key.
	/// </summary>
	/// <param name="publicKeyFile">The key used to encrypt the data</param>
	/// <param name="privateKeyFile">The key used to sign the data.</param>
	/// <param name="passPhrase">The password required to access the private key</param>
	/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
	public EncryptionKeys(FileInfo publicKeyFile, FileInfo privateKeyFile, string passPhrase)
	{
		if (publicKeyFile == null)
			throw new ArgumentNullException(nameof(publicKeyFile));

		if (privateKeyFile == null)
			throw new ArgumentNullException(nameof(privateKeyFile));

		if (passPhrase == null)
			throw new ArgumentNullException(nameof(passPhrase));

		if (!publicKeyFile.Exists)
			throw new FileNotFoundException(string.Format("Public Key file [{0}] does not exist.", publicKeyFile.FullName));

		if (!privateKeyFile.Exists)
			throw new FileNotFoundException(string.Format("Private Key file [{0}] does not exist.", privateKeyFile.FullName));

		_publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
		{
			return new List<PgpPublicKey>() { Utilities.ReadPublicKey(publicKeyFile) };
		});

		_secretKeys = new Lazy<PgpSecretKeyRingBundle?>(() =>
		{
			using var inputStream = PgpUtilities.GetDecoderStream(privateKeyFile.OpenRead());
			return new PgpSecretKeyRingBundle(inputStream);
		});

		_secretKey = new Lazy<PgpSecretKey?>(() =>
		{
			return ReadSecretKey();
		});

		_privateKey = new Lazy<PgpPrivateKey?>(() =>
		{
			return ReadPrivateKey(passPhrase);
		});

		_passPhrase = passPhrase;
	}

	/// <summary>
	/// Initializes a new instance of the EncryptionKeys class.
	/// Two or more keys are required to encrypt and sign data. Your private key and the recipients public key(s).
	/// The data is encrypted with the recipients public key(s) and signed with your private key.
	/// </summary>
	/// <param name="publicKeys">The key(s) used to encrypt the data</param>
	/// <param name="privateKey">The key used to sign the data.</param>
	/// <param name="passPhrase">The password required to access the private key</param>
	/// <param name="encoding"></param>
	/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
	public EncryptionKeys(IEnumerable<string> publicKeys, string privateKey, string passPhrase, Encoding? encoding = null)
	{
		if (string.IsNullOrEmpty(privateKey))
			throw new ArgumentNullException(nameof(privateKey));

		if (passPhrase == null)
			throw new ArgumentNullException(nameof(passPhrase));

		foreach (string publicKey in publicKeys)
		{
			if (string.IsNullOrEmpty(publicKey))
				throw new ArgumentException(nameof(publicKey));
		}

		_publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
		{
			return publicKeys.Select(x => Utilities.ReadPublicKey(x.GetStream(encoding))).ToList();
		});

		_secretKeys = new Lazy<PgpSecretKeyRingBundle?>(() =>
		{
			using var inputStream = PgpUtilities.GetDecoderStream(privateKey.GetStream(encoding));
			return new PgpSecretKeyRingBundle(inputStream);
		});

		_secretKey = new Lazy<PgpSecretKey?>(() =>
		{
			return ReadSecretKey();
		});

		_privateKey = new Lazy<PgpPrivateKey?>(() =>
		{
			return ReadPrivateKey(passPhrase);
		});

		_passPhrase = passPhrase;
	}

	/// <summary>
	/// Initializes a new instance of the EncryptionKeys class.
	/// Two or more keys are required to encrypt and sign data. Your private key and the recipients public key(s).
	/// The data is encrypted with the recipients public key(s) and signed with your private key.
	/// </summary>
	/// <param name="publicKeyFiles">The key(s) used to encrypt the data</param>
	/// <param name="privateKeyFile">The key used to sign the data.</param>
	/// <param name="passPhrase">The password required to access the private key</param>
	/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
	public EncryptionKeys(IEnumerable<FileInfo> publicKeyFiles, FileInfo privateKeyFile, string passPhrase)
	{
		// Avoid multiple enumerations of 'publicKeyFilePaths'
		var publicKeys = publicKeyFiles.ToArray();

		if (privateKeyFile == null)
			throw new ArgumentNullException(nameof(privateKeyFile));

		if (passPhrase == null)
			throw new ArgumentNullException(nameof(passPhrase));

		if (!privateKeyFile.Exists)
			throw new FileNotFoundException(string.Format("Private Key file [{0}] does not exist.", privateKeyFile.FullName));

		foreach (FileInfo publicKeyFile in publicKeys)
		{
			if (publicKeyFile == null)
				throw new ArgumentException(nameof(publicKeyFile.FullName));

			if (!File.Exists(publicKeyFile.FullName))
				throw new FileNotFoundException(string.Format("Input file [{0}] does not exist.", publicKeyFile.FullName));
		}

		_publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
		{
			return publicKeyFiles.Select(x => Utilities.ReadPublicKey(x)).ToList();
		});

		_secretKeys = new Lazy<PgpSecretKeyRingBundle?>(() =>
		{
			using var inputStream = PgpUtilities.GetDecoderStream(privateKeyFile.OpenRead());
			return new PgpSecretKeyRingBundle(inputStream);
		});

		_secretKey = new Lazy<PgpSecretKey?>(() =>
		{
			return ReadSecretKey();
		});

		_privateKey = new Lazy<PgpPrivateKey?>(() =>
		{
			return ReadPrivateKey(passPhrase);
		});

		_passPhrase = passPhrase;
	}

	public EncryptionKeys(string privateKey, string passPhrase, Encoding? encoding = null)
	{
		if (string.IsNullOrEmpty(privateKey))
			throw new ArgumentNullException(nameof(privateKey));

		if (passPhrase == null)
			throw new ArgumentNullException(nameof(passPhrase));

		_publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
		{
			return Array.Empty<PgpPublicKey>();
		});

		_secretKeys = new Lazy<PgpSecretKeyRingBundle?>(() =>
		{
			using Stream inputStream = PgpUtilities.GetDecoderStream(privateKey.GetStream(encoding));
			return new PgpSecretKeyRingBundle(inputStream);
		});

		_secretKey = new Lazy<PgpSecretKey?>(() =>
		{
			return ReadSecretKey();
		});

		_privateKey = new Lazy<PgpPrivateKey?>(() =>
		{
			return ReadPrivateKey(passPhrase);
		});

		_passPhrase = passPhrase;
	}

	public EncryptionKeys(FileInfo privateKeyFile, string passPhrase)
	{
		if (privateKeyFile is null)
			throw new ArgumentNullException(nameof(privateKeyFile));

		if (passPhrase == null)
			throw new ArgumentNullException(nameof(passPhrase));

		if (!privateKeyFile.Exists)
			throw new FileNotFoundException(string.Format("Private Key file [{0}] does not exist.", privateKeyFile.FullName));

		_publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
		{
			return Array.Empty<PgpPublicKey>();
		});

		_secretKeys = new Lazy<PgpSecretKeyRingBundle?>(() =>
		{
			using var inputStream = PgpUtilities.GetDecoderStream(privateKeyFile.OpenRead());
			return new PgpSecretKeyRingBundle(inputStream);
		});

		_secretKey = new Lazy<PgpSecretKey?>(() =>
		{
			return ReadSecretKey();
		});

		_privateKey = new Lazy<PgpPrivateKey?>(() =>
		{
			return ReadPrivateKey(passPhrase);
		});

		_passPhrase = passPhrase;
	}

	public EncryptionKeys(Stream publicKeyStream, Stream privateKeyStream, string passPhrase)
	{
		if (publicKeyStream == null)
			throw new ArgumentNullException(nameof(publicKeyStream));

		if (privateKeyStream == null)
			throw new ArgumentNullException(nameof(privateKeyStream));

		if (passPhrase == null)
			throw new ArgumentNullException(nameof(passPhrase));

		_publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
		{
			return new List<PgpPublicKey>() { Utilities.ReadPublicKey(publicKeyStream) };
		});

		_secretKeys = new Lazy<PgpSecretKeyRingBundle?>(() =>
		{
			using var inputStream = PgpUtilities.GetDecoderStream(privateKeyStream);
			return new PgpSecretKeyRingBundle(inputStream);
		});

		_secretKey = new Lazy<PgpSecretKey?>(() =>
		{
			return ReadSecretKey();
		});

		_privateKey = new Lazy<PgpPrivateKey?>(() =>
		{
			return ReadPrivateKey(passPhrase);
		});

		_passPhrase = passPhrase;
	}

	public EncryptionKeys(Stream privateKeyStream, string passPhrase)
	{
		if (privateKeyStream == null)
			throw new ArgumentNullException(nameof(privateKeyStream));

		if (passPhrase == null)
			throw new ArgumentNullException(nameof(passPhrase));

		_publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
		{
			return Array.Empty<PgpPublicKey>();
		});

		_secretKeys = new Lazy<PgpSecretKeyRingBundle?>(() =>
		{
			using var inputStream = PgpUtilities.GetDecoderStream(privateKeyStream);
			return new PgpSecretKeyRingBundle(inputStream);
		});

		_secretKey = new Lazy<PgpSecretKey?>(() =>
		{
			return ReadSecretKey();
		});

		_privateKey = new Lazy<PgpPrivateKey?>(() =>
		{
			return ReadPrivateKey(passPhrase);
		});

		_passPhrase = passPhrase;
	}

	public EncryptionKeys(IEnumerable<Stream> publicKeyStreams, Stream privateKeyStream, string passPhrase)
	{
		// Avoid multiple enumerations of 'publicKeyFilePaths'
		var publicKeys = publicKeyStreams.ToArray();

		if (privateKeyStream == null)
			throw new ArgumentNullException(nameof(privateKeyStream));

		if (passPhrase == null)
			throw new ArgumentNullException(nameof(privateKeyStream));

		foreach (Stream publicKey in publicKeys)
		{
			if (publicKey == null)
				throw new ArgumentException("PublicKeyStream");
		}

		_publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
		{
			return publicKeyStreams.Select(x => Utilities.ReadPublicKey(x)).ToList();
		});

		_secretKeys = new Lazy<PgpSecretKeyRingBundle?>(() =>
		{
			using var inputStream = PgpUtilities.GetDecoderStream(privateKeyStream);
			return new PgpSecretKeyRingBundle(inputStream);
		});

		_secretKey = new Lazy<PgpSecretKey?>(() =>
		{
			return ReadSecretKey();
		});

		_privateKey = new Lazy<PgpPrivateKey?>(() =>
		{
			return ReadPrivateKey(passPhrase);
		});

		_passPhrase = passPhrase;
	}

	/// <summary>
	/// Initializes a new instance of the EncryptionKeys class.
	/// Two keys are required to encrypt and sign data. Your private key and the recipients public key.
	/// The data is encrypted with the recipients public key and signed with your private key.
	/// </summary>
	/// <param name="publicKey">The key used to encrypt the data</param>
	/// <param name="encoding"></param>
	/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
	public EncryptionKeys(string publicKey, Encoding? encoding = null)
	{
		if (string.IsNullOrEmpty(publicKey))
			throw new ArgumentNullException(nameof(publicKey));

		_publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
		{
			return new List<PgpPublicKey>() { Utilities.ReadPublicKey(publicKey.GetStream(encoding)) };
		});

		_secretKeys = new Lazy<PgpSecretKeyRingBundle?>(() =>
		{
			return null;
		});

		_secretKey = new Lazy<PgpSecretKey?>(() =>
		{
			return null;
		});

		_privateKey = new Lazy<PgpPrivateKey?>(() =>
		{
			return null;
		});

		_passPhrase = null;
	}

	/// <summary>
	/// Initializes a new instance of the EncryptionKeys class.
	/// Two keys are required to encrypt and sign data. Your private key and the recipients public key.
	/// The data is encrypted with the recipients public key and signed with your private key.
	/// </summary>
	/// <param name="publicKeyFile">The key used to encrypt the data</param>
	/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
	public EncryptionKeys(FileInfo publicKeyFile)
	{
		if (publicKeyFile == null)
			throw new ArgumentException("PublicKeyFilePath");

		if (!publicKeyFile.Exists)
			throw new FileNotFoundException(string.Format("Public Key file [{0}] does not exist.", publicKeyFile.FullName));

		_publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
		{
			return new List<PgpPublicKey>() { Utilities.ReadPublicKey(publicKeyFile) };
		});

		_secretKeys = new Lazy<PgpSecretKeyRingBundle?>(() =>
		{
			return null;
		});

		_secretKey = new Lazy<PgpSecretKey?>(() =>
		{
			return null;
		});

		_privateKey = new Lazy<PgpPrivateKey?>(() =>
		{
			return null;
		});

		_passPhrase = null;
	}

	/// <summary>
	/// Initializes a new instance of the EncryptionKeys class.
	/// Two keys are required to encrypt and sign data. Your private key and the recipients public key.
	/// The data is encrypted with the recipients public key and signed with your private key.
	/// </summary>
	/// <param name="publicKeys">The keys used to encrypt the data</param>
	/// <param name="encoding"></param>
	/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
	public EncryptionKeys(IEnumerable<string> publicKeys, Encoding? encoding = null)
	{
		foreach (string publicKey in publicKeys)
		{
			if (string.IsNullOrEmpty(publicKey))
				throw new ArgumentException(nameof(publicKey));
		}

		_publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
		{
			return publicKeys.Select(x => Utilities.ReadPublicKey(x.GetStream(encoding))).ToList();
		});

		_secretKeys = new Lazy<PgpSecretKeyRingBundle?>(() =>
		{
			return null;
		});

		_secretKey = new Lazy<PgpSecretKey?>(() =>
		{
			return null;
		});

		_privateKey = new Lazy<PgpPrivateKey?>(() =>
		{
			return null;
		});

		_passPhrase = null;
	}

	/// <summary>
	/// Initializes a new instance of the EncryptionKeys class.
	/// Two keys are required to encrypt and sign data. Your private key and the recipients public key.
	/// The data is encrypted with the recipients public key and signed with your private key.
	/// </summary>
	/// <param name="publicKeyFiles">The keys used to encrypt the data</param>
	/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
	public EncryptionKeys(IEnumerable<FileInfo> publicKeyFiles)
	{
		// Avoid multiple enumerations of 'publicKeyFiles'
		FileInfo[] publicKeys = publicKeyFiles.ToArray();

		foreach (FileInfo publicKeyFile in publicKeys)
		{
			if (publicKeyFile is null)
				throw new ArgumentException(nameof(publicKeyFile));
			if (!publicKeyFile.Exists)
				throw new FileNotFoundException(string.Format("Input file [{0}] does not exist.", publicKeyFile.FullName));
		}

		_publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
		{
			return publicKeyFiles.Select(x => Utilities.ReadPublicKey(x)).ToList();
		});

		_secretKeys = new Lazy<PgpSecretKeyRingBundle?>(() =>
		{
			return null;
		});

		_secretKey = new Lazy<PgpSecretKey?>(() =>
		{
			return null;
		});

		_privateKey = new Lazy<PgpPrivateKey?>(() =>
		{
			return null;
		});

		_passPhrase = null;
	}

	public EncryptionKeys(Stream publicKeyStream)
	{
		if (publicKeyStream == null)
			throw new ArgumentException("PublicKeyStream");

		_publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
		{
			return new List<PgpPublicKey>() { Utilities.ReadPublicKey(publicKeyStream) };
		});

		_secretKeys = new Lazy<PgpSecretKeyRingBundle?>(() =>
		{
			return null;
		});

		_secretKey = new Lazy<PgpSecretKey?>(() =>
		{
			return null;
		});

		_privateKey = new Lazy<PgpPrivateKey?>(() =>
		{
			return null;
		});

		_passPhrase = null;
	}

	public EncryptionKeys(IEnumerable<Stream> publicKeyStreams)
	{
		Stream[] publicKeys = publicKeyStreams.ToArray();

		foreach (Stream publicKey in publicKeys)
		{
			if (publicKey == null)
				throw new ArgumentException("PublicKeyStream");
		}

		_publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
		{
			return publicKeyStreams.Select(x => Utilities.ReadPublicKey(x)).ToList();
		});

		_secretKeys = new Lazy<PgpSecretKeyRingBundle?>(() =>
		{
			return null;
		});

		_secretKey = new Lazy<PgpSecretKey?>(() =>
		{
			return null;
		});

		_privateKey = new Lazy<PgpPrivateKey?>(() =>
		{
			return null;
		});

		_passPhrase = null;
	}

	public PgpPrivateKey? FindSecretKey(long keyId)
	{
		if (_passPhrase == null)
			return null;

		var pgpSecKey = SecretKeys?.GetSecretKey(keyId);

		if (pgpSecKey == null)
			return null;

		return pgpSecKey.ExtractPrivateKey(_passPhrase.ToCharArray());
	}

	private PgpSecretKey ReadSecretKey()
	{
		var foundKey = GetFirstSecretKey(SecretKeys);
		if (foundKey != null)
			return foundKey;

		throw new InvalidOperationException("Can't find signing key in key ring.");
	}

	/// <summary>
	/// Return the first key we can use to encrypt.
	/// Note: A file can contain multiple keys (stored in "key rings")
	/// </summary>
	private static PgpSecretKey? GetFirstSecretKey(PgpSecretKeyRingBundle? secretKeyRingBundle)
	{
		if (secretKeyRingBundle == null)
			return null;

		foreach (PgpSecretKeyRing kRing in secretKeyRingBundle.GetKeyRings())
		{
			var key = kRing.GetSecretKeys()
				.Cast<PgpSecretKey>()
				.Where(k => k.IsSigningKey)
				.FirstOrDefault();

			if (key != null)
				return key;
		}
		return null;
	}

	private PgpPrivateKey ReadPrivateKey(string passPhrase)
	{
		var privateKey = SecretKey?.ExtractPrivateKey(passPhrase.ToCharArray());
		if (privateKey != null)
			return privateKey;

		throw new ArgumentException("No private key found in secret key.");
	}
}
