using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using System.Text;

namespace Envelope.Cryptography.PGP.Internal;

/// <remarks>Basic utility class.</remarks>
internal static class Utilities
{
	private const int ReadAhead = 60;
	private const int encryptKeyFlags = PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage;

	public static MPInteger[] DsaSigToMpi(byte[] encoding)
	{
		DerInteger i1, i2;

		try
		{
			var s = (Asn1Sequence)Asn1Object.FromByteArray(encoding);

			i1 = (DerInteger)s[0];
			i2 = (DerInteger)s[1];
		}
		catch (IOException e)
		{
			throw new PgpException("Exception encoding signature", e);
		}

		return new MPInteger[] { new MPInteger(i1.Value), new MPInteger(i2.Value) };
	}

	public static MPInteger[] RsaSigToMpi(byte[] encoding)
		=> new MPInteger[] { new MPInteger(new BigInteger(1, encoding)) };

	public static string GetDigestName(HashAlgorithmTag hashAlgorithm)
		=> hashAlgorithm switch
		{
			HashAlgorithmTag.Sha1 => "SHA1",
			HashAlgorithmTag.MD2 => "MD2",
			HashAlgorithmTag.MD5 => "MD5",
			HashAlgorithmTag.RipeMD160 => "RIPEMD160",
			HashAlgorithmTag.Sha224 => "SHA224",
			HashAlgorithmTag.Sha256 => "SHA256",
			HashAlgorithmTag.Sha384 => "SHA384",
			HashAlgorithmTag.Sha512 => "SHA512",
			_ => throw new PgpException($"Unknown hash algorithm tag in GetDigestName: {hashAlgorithm}"),
		};

	public static string GetSignatureName(PublicKeyAlgorithmTag keyAlgorithm, HashAlgorithmTag hashAlgorithm)
	{
		var encAlg = keyAlgorithm switch
		{
			PublicKeyAlgorithmTag.RsaGeneral
				or PublicKeyAlgorithmTag.RsaSign => "RSA",
			PublicKeyAlgorithmTag.Dsa => "DSA",
			PublicKeyAlgorithmTag.ECDH => "ECDH",
			PublicKeyAlgorithmTag.ECDsa => "ECDSA",
			// in some malformed cases.
			PublicKeyAlgorithmTag.ElGamalEncrypt
				or PublicKeyAlgorithmTag.ElGamalGeneral => "ElGamal",
			_ => throw new PgpException($"Unknown algorithm tag in signature: {keyAlgorithm}"),
		};
		return $"{GetDigestName(hashAlgorithm)} with {encAlg}";
	}

	public static string GetSymmetricCipherName(SymmetricKeyAlgorithmTag algorithm)
		=> algorithm != SymmetricKeyAlgorithmTag.Null
			? algorithm switch
				{
					SymmetricKeyAlgorithmTag.TripleDes => "DESEDE",
					SymmetricKeyAlgorithmTag.Idea => "IDEA",
					SymmetricKeyAlgorithmTag.Cast5 => "CAST5",
					SymmetricKeyAlgorithmTag.Blowfish => "Blowfish",
					SymmetricKeyAlgorithmTag.Safer => "SAFER",
					SymmetricKeyAlgorithmTag.Des => "DES",
					SymmetricKeyAlgorithmTag.Aes128 => "AES",
					SymmetricKeyAlgorithmTag.Aes192 => "AES",
					SymmetricKeyAlgorithmTag.Aes256 => "AES",
					SymmetricKeyAlgorithmTag.Twofish => "Twofish",
					SymmetricKeyAlgorithmTag.Camellia128 => "Camellia",
					SymmetricKeyAlgorithmTag.Camellia192 => "Camellia",
					SymmetricKeyAlgorithmTag.Camellia256 => "Camellia",
					_ => throw new PgpException($"Unknown symmetric algorithm: {algorithm}"),
				}
			: throw new ArgumentNullException(nameof(algorithm));

	public static int GetKeySize(SymmetricKeyAlgorithmTag algorithm)
		=> algorithm switch
		{
			SymmetricKeyAlgorithmTag.Des => 64,
			SymmetricKeyAlgorithmTag.Idea
				or SymmetricKeyAlgorithmTag.Cast5
				or SymmetricKeyAlgorithmTag.Blowfish
				or SymmetricKeyAlgorithmTag.Safer
				or SymmetricKeyAlgorithmTag.Aes128
				or SymmetricKeyAlgorithmTag.Camellia128 => 128,
			SymmetricKeyAlgorithmTag.TripleDes
				or SymmetricKeyAlgorithmTag.Aes192
				or SymmetricKeyAlgorithmTag.Camellia192 => 192,
			SymmetricKeyAlgorithmTag.Aes256
				or SymmetricKeyAlgorithmTag.Twofish
				or SymmetricKeyAlgorithmTag.Camellia256 => 256,
			_ => throw new PgpException($"Unknown symmetric algorithm: {algorithm}"),
		};

	public static KeyParameter MakeKey(SymmetricKeyAlgorithmTag algorithm, byte[] keyBytes)
	{
		var algName = GetSymmetricCipherName(algorithm);
		return ParameterUtilities.CreateKeyParameter(algName, keyBytes);
	}

	public static KeyParameter MakeRandomKey(SymmetricKeyAlgorithmTag algorithm, SecureRandom random)
	{
		var keySize = GetKeySize(algorithm);
		var keyBytes = new byte[(keySize + 7) / 8];
		random.NextBytes(keyBytes);
		return MakeKey(algorithm, keyBytes);
	}

	public static KeyParameter MakeKeyFromPassPhrase(SymmetricKeyAlgorithmTag algorithm, S2k s2k, char[] passPhrase)
	{
		var keySize = GetKeySize(algorithm);
		var pBytes = Strings.ToByteArray(new string(passPhrase));
		var keyBytes = new byte[(keySize + 7) / 8];

		var generatedBytes = 0;
		var loopCount = 0;

		while (generatedBytes < keyBytes.Length)
		{
			IDigest digest;
			if (s2k != null)
			{
				var digestName = GetDigestName(s2k.HashAlgorithm);

				try
				{
					digest = DigestUtilities.GetDigest(digestName);
				}
				catch (Exception e)
				{
					throw new PgpException("can't find S2k digest", e);
				}

				for (int i = 0; i != loopCount; i++)
					digest.Update(0);

				var iv = s2k.GetIV();

				switch (s2k.Type)
				{
					case S2k.Simple:
						digest.BlockUpdate(pBytes, 0, pBytes.Length);
						break;
					case S2k.Salted:
						digest.BlockUpdate(iv, 0, iv.Length);
						digest.BlockUpdate(pBytes, 0, pBytes.Length);
						break;
					case S2k.SaltedAndIterated:
						var count = s2k.IterationCount;
						digest.BlockUpdate(iv, 0, iv.Length);
						digest.BlockUpdate(pBytes, 0, pBytes.Length);

						count -= iv.Length + pBytes.Length;

						while (0 < count)
						{
							if (count < iv.Length)
							{
								digest.BlockUpdate(iv, 0, (int)count);
								break;
							}
							else
							{
								digest.BlockUpdate(iv, 0, iv.Length);
								count -= iv.Length;
							}

							if (count < pBytes.Length)
							{
								digest.BlockUpdate(pBytes, 0, (int)count);
								count = 0;
							}
							else
							{
								digest.BlockUpdate(pBytes, 0, pBytes.Length);
								count -= pBytes.Length;
							}
						}
						break;
					default:
						throw new PgpException($"Unknown S2k type: {s2k.Type}");
				}
			}
			else
			{
				try
				{
					digest = DigestUtilities.GetDigest("MD5");

					for (int i = 0; i != loopCount; i++)
						digest.Update(0);

					digest.BlockUpdate(pBytes, 0, pBytes.Length);
				}
				catch (Exception e)
				{
					throw new PgpException("can't find MD5 digest", e);
				}
			}

			var dig = DigestUtilities.DoFinal(digest);

			if (dig.Length > (keyBytes.Length - generatedBytes))
				Array.Copy(dig, 0, keyBytes, generatedBytes, keyBytes.Length - generatedBytes);
			else
				Array.Copy(dig, 0, keyBytes, generatedBytes, dig.Length);

			generatedBytes += dig.Length;

			loopCount++;
		}

		Array.Clear(pBytes, 0, pBytes.Length);
		return MakeKey(algorithm, keyBytes);
	}

	/// <summary>Write out the passed in file as a literal data packet.</summary>
	public static async Task WriteFileToLiteralDataAsync(Stream output, char fileType, FileInfo file, CancellationToken cancellationToken)
	{
		var lData = new PgpLiteralDataGenerator();
		var pOut = lData.Open(output, fileType, file.Name, file.Length, file.LastWriteTime);
		await PipeFileContentsAsync(file, pOut, 4096, cancellationToken);
		lData.Close();
	}

	/// <summary>Write out the passed in file as a literal data packet.</summary>
	public static void WriteFileToLiteralData(Stream output, char fileType, FileInfo file)
	{
		var lData = new PgpLiteralDataGenerator();
		var pOut = lData.Open(output, fileType, file.Name, file.Length, file.LastWriteTime);
		PipeFileContents(file, pOut, 4096);
		lData.Close();
	}

	/// <summary>Write out the passed in file as a literal data packet in partial packet format.</summary>
	public static async Task WriteFileToLiteralDataAsync(
		Stream output,
		char fileType,
		FileInfo file,
		byte[] buffer,
		CancellationToken cancellationToken)
	{
		var lData = new PgpLiteralDataGenerator();
		var pOut = lData.Open(output, fileType, file.Name, file.LastWriteTime, buffer);
		await PipeFileContentsAsync(file, pOut, buffer.Length, cancellationToken);
		lData.Close();
	}

	/// <summary>Write out the passed in file as a literal data packet in partial packet format.</summary>
	public static void WriteFileToLiteralData(
		Stream output,
		char fileType,
		FileInfo file,
		byte[] buffer)
	{
		var lData = new PgpLiteralDataGenerator();
		var pOut = lData.Open(output, fileType, file.Name, file.LastWriteTime, buffer);
		PipeFileContents(file, pOut, buffer.Length);
		lData.Close();
	}

	public static async Task WriteStreamToLiteralDataAsync(
		Stream output,
		char fileType,
		Stream input,
		string name,
		CancellationToken cancellationToken)
	{
		var lData = new PgpLiteralDataGenerator();
		var pOut = lData.Open(output, fileType, name, input.Length, DateTime.Now);
		await PipeStreamContentsAsync(input, pOut, 4096, cancellationToken);
		lData.Close();
	}

	public static void WriteStreamToLiteralData(
		Stream output,
		char fileType,
		Stream input,
		string name)
	{
		var lData = new PgpLiteralDataGenerator();
		var pOut = lData.Open(output, fileType, name, input.Length, DateTime.Now);
		PipeStreamContents(input, pOut, 4096);
		lData.Close();
	}

	public static async Task WriteStreamToLiteralDataAsync(
		Stream output,
		char fileType,
		Stream input,
		byte[] buffer,
		string name,
		CancellationToken cancellationToken)
	{
		var lData = new PgpLiteralDataGenerator();
		var pOut = lData.Open(output, fileType, name, DateTime.Now, buffer);
		await PipeStreamContentsAsync(input, pOut, buffer.Length, cancellationToken);
		lData.Close();
	}

	public static void WriteStreamToLiteralData(
		Stream output,
		char fileType,
		Stream input,
		byte[] buffer,
		string name)
	{
		var lData = new PgpLiteralDataGenerator();
		var pOut = lData.Open(output, fileType, name, DateTime.Now, buffer);
		PipeStreamContents(input, pOut, buffer.Length);
		lData.Close();
	}

	/// <summary>
	/// Opens a key ring file and returns first available sub-key suitable for encryption.
	/// If such sub-key is not found, return master key that can encrypt.
	/// </summary>
	/// <param name="publicKeyStream">Input stream containing the public key contents</param>
	/// <returns></returns>
	public static PgpPublicKey ReadPublicKey(Stream publicKeyStream)
	{
		using var inputStream = PgpUtilities.GetDecoderStream(publicKeyStream);
		var pgpPub = new PgpPublicKeyRingBundle(inputStream);

		// we just loop through the collection till we find a key suitable for encryption, in the real
		// world you would probably want to be a bit smarter about this.
		// iterate through the key rings.
		foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
		{
			var keys = kRing.GetPublicKeys()
				.Cast<PgpPublicKey>()
				.Where(k => k.IsEncryptionKey).ToList();

			foreach (PgpPublicKey key in keys.Where(k => k.Version >= 4 && k.IsMasterKey))
				foreach (PgpSignature s in key.GetSignatures())
					if (s.HasSubpackets && s.GetHashedSubPackets().GetKeyFlags() == encryptKeyFlags)
						return key;

			if (keys.Any())
				return keys.First();
		}

		throw new ArgumentException("Can't find encryption key in key ring.");
	}

	/// <summary>
	/// Parses a public key
	/// </summary>
	/// <param name="publicKey">The plain text value of the public key</param>
	/// <param name="encoding"></param>
	/// <returns></returns>
	public static PgpPublicKey ReadPublicKey(string publicKey, Encoding? encoding = null)
	{
		if (string.IsNullOrEmpty(publicKey))
			throw new FileNotFoundException("Public key was not provided");

		return ReadPublicKey(publicKey.GetStream(encoding));
	}

	/// <summary>
	/// Parses a public key
	/// </summary>
	/// <param name="publicKeyFile">The path to the public key file</param>
	/// <returns></returns>
	public static PgpPublicKey ReadPublicKey(FileInfo publicKeyFile)
	{
		if (!publicKeyFile.Exists)
			throw new FileNotFoundException(string.Format("File {0} was not found", publicKeyFile));

		using var fs = publicKeyFile.OpenRead();
		return ReadPublicKey(fs);
	}

	private static async Task PipeFileContentsAsync(FileInfo file, Stream pOut, int bufSize, CancellationToken cancellationToken)
	{
		using var inputStream = file.OpenRead();
		var buf = new byte[bufSize];

		int len;
#if NETSTANDARD2_0 || NETSTANDARD2_1
		while (0 < (len = await inputStream.ReadAsync(buf, 0, buf.Length, cancellationToken)))
			await pOut.WriteAsync(buf, 0, len, cancellationToken);
#elif NET6_0_OR_GREATER
		while (0 < (len = await inputStream.ReadAsync(buf, cancellationToken)))
			await pOut.WriteAsync(buf.AsMemory(0, len), cancellationToken);
#endif
	}

	private static void PipeFileContents(FileInfo file, Stream pOut, int bufSize)
	{
		using var inputStream = file.OpenRead();
		var buf = new byte[bufSize];

		int len;
		while (0 < (len = inputStream.Read(buf, 0, buf.Length)))
			pOut.Write(buf, 0, len);
	}

	private static async Task PipeStreamContentsAsync(Stream input, Stream pOut, int bufSize, CancellationToken cancellationToken)
	{
		var buf = new byte[bufSize];

		int len;
#if NETSTANDARD2_0 || NETSTANDARD2_1
		while (0 < (len = await input.ReadAsync(buf, 0, buf.Length, cancellationToken)))
			await pOut.WriteAsync(buf, 0, len, cancellationToken);
#elif NET6_0_OR_GREATER
		while (0 < (len = await input.ReadAsync(buf, cancellationToken)))
			await pOut.WriteAsync(buf.AsMemory(0, len), cancellationToken);
#endif
	}

	private static void PipeStreamContents(Stream input, Stream pOut, int bufSize)
	{
		var buf = new byte[bufSize];

		int len;
		while (0 < (len = input.Read(buf, 0, buf.Length)))
			pOut.Write(buf, 0, len);
	}

	private static bool IsPossiblyBase64(int ch)
		=> (ch >= 'A' && ch <= 'Z')
			|| (ch >= 'a' && ch <= 'z')
			|| (ch >= '0' && ch <= '9')
			|| (ch == '+')
			|| (ch == '/')
			|| (ch == '\r')
			|| (ch == '\n');

	/// <summary>
	/// Return either an ArmoredInputStream or a BcpgInputStream based on whether
	/// the initial characters of the stream are binary PGP encodings or not.
	/// </summary>
	public static Stream GetDecoderStream(Stream inputStream)
	{
		// TODO Remove this restriction?
		if (!inputStream.CanSeek)
			throw new ArgumentException("inputStream must be seek-able", nameof(inputStream));

		var markedPos = inputStream.Position;

		var ch = inputStream.ReadByte();
		if ((ch & 0x80) != 0)
		{
			inputStream.Position = markedPos;
			return inputStream;
		}
		else
		{
			if (!IsPossiblyBase64(ch))
			{
				inputStream.Position = markedPos;
				return new ArmoredInputStream(inputStream);
			}

			var buf = new byte[ReadAhead];
			var count = 1;
			var index = 1;

			buf[0] = (byte)ch;
			while (count != ReadAhead && (ch = inputStream.ReadByte()) >= 0)
			{
				if (!IsPossiblyBase64(ch))
				{
					inputStream.Position = markedPos;
					return new ArmoredInputStream(inputStream);
				}

				if (ch != '\n' && ch != '\r')
					buf[index++] = (byte)ch;

				count++;
			}

			inputStream.Position = markedPos;

			//
			// nothing but new lines, little else, assume regular armoring
			//
			if (count < 4)
				return new ArmoredInputStream(inputStream);

			//
			// test our non-blank data
			//
			var firstBlock = new byte[8];
			Array.Copy(buf, 0, firstBlock, 0, firstBlock.Length);
			var decoded = Base64.Decode(firstBlock);

			//
			// it's a base64 PGP block.
			//
			var hasHeaders = (decoded[0] & 0x80) == 0;

			return new ArmoredInputStream(inputStream, hasHeaders);
		}
	}

	public static PgpPublicKeyEncryptedData? ExtractPublicKeyEncryptedData(System.IO.Stream encodedFile)
	{
		var encryptedDataList = GetEncryptedDataList(encodedFile);
		var publicKeyED = ExtractPublicKey(encryptedDataList);
		return publicKeyED;
	}

	public static PgpPublicKeyEncryptedData? ExtractPublicKeyEncryptedData(PgpEncryptedDataList encryptedDataList)
	{
		var publicKeyED = ExtractPublicKey(encryptedDataList);
		return publicKeyED;
	}

	public static PgpObject ProcessCompressedMessage(PgpObject message)
	{
		var compressedData = (PgpCompressedData)message;
		var compressedDataStream = compressedData.GetDataStream();
		var compressedFactory = new PgpObjectFactory(compressedDataStream);
		message = CheckForOnePassSignatureList(compressedFactory);
		return message;
	}

	public static PgpObject CheckForOnePassSignatureList(PgpObjectFactory compressedFactory)
	{
		var message = compressedFactory.NextPgpObject();
		if (message is PgpOnePassSignatureList)
			message = compressedFactory.NextPgpObject();

		return message;
	}

	public static PgpObject SkipSignatureList(PgpObjectFactory compressedFactory)
	{
		var message = compressedFactory.NextPgpObject();
		while (message is PgpOnePassSignatureList || message is PgpSignatureList)
			message = compressedFactory.NextPgpObject();

		return message;
	}

	internal static PgpObject GetClearCompressedMessage(PgpPublicKeyEncryptedData publicKeyED, EncryptionKeys encryptionKeys)
	{
		if (encryptionKeys.PrivateKey == null)
			throw new InvalidOperationException("encryptionKeys.PrivateKey == null");

		var clearFactory = GetClearDataStream(encryptionKeys.PrivateKey, publicKeyED);
		var message = clearFactory.NextPgpObject();
		if (message is PgpOnePassSignatureList)
			message = clearFactory.NextPgpObject();

		return message;
	}

	public static PgpObjectFactory GetClearDataStream(PgpPrivateKey privateKey, PgpPublicKeyEncryptedData publicKeyED)
	{
		var clearStream = publicKeyED.GetDataStream(privateKey);
		var clearFactory = new PgpObjectFactory(clearStream);
		return clearFactory;
	}

	public static PgpPublicKeyEncryptedData? ExtractPublicKey(PgpEncryptedDataList encryptedDataList)
	{
		PgpPublicKeyEncryptedData? publicKeyED = null;
		foreach (PgpPublicKeyEncryptedData privateKeyED in encryptedDataList.GetEncryptedDataObjects())
		{
			if (privateKeyED != null)
			{
				publicKeyED = privateKeyED;
				break;
			}
		}
		return publicKeyED;
	}

	public static PgpEncryptedDataList GetEncryptedDataList(Stream encodedFile)
	{
		var factory = new PgpObjectFactory(encodedFile);
		var pgpObject = factory.NextPgpObject();

		var encryptedDataList = pgpObject is PgpEncryptedDataList list
			? list
			: (PgpEncryptedDataList)factory.NextPgpObject();

		return encryptedDataList;
	}

	public static PgpOnePassSignatureList GetPgpOnePassSignatureList(Stream encodedFile)
	{
		var factory = new PgpObjectFactory(encodedFile);
		var pgpObject = factory.NextPgpObject();

		var pgpOnePassSignatureList = pgpObject is PgpOnePassSignatureList list
			? list
			: (PgpOnePassSignatureList)factory.NextPgpObject();

		return pgpOnePassSignatureList;
	}
}
