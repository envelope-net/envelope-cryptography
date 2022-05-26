using Envelope.Cryptography.PGP.Internal;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.Text;

namespace Envelope.Cryptography.PGP;

public partial class PGPProvider : IPGPEncrypt, IPGPEncryptAndSign, IPGPSign, IPGPClearSign, IPGPDecrypt, IPGPDecryptAndVerify, IPGPGetRecipients, IPGPGenerateKey
{
	/// <inheritdoc />
	public Stream DecryptStreamAndVerify(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys)
	{
		if (inputStream == null)
			throw new ArgumentNullException(nameof(inputStream));

		if (outputStream == null)
			throw new ArgumentNullException(nameof(outputStream));

		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		if (encryptionKeys.PublicKey == null)
			throw new InvalidOperationException("encryptionKeys.PublicKey == null");


		if (inputStream.Position != 0)
			throw new ArgumentException($"{nameof(inputStream)} should be at start of stream", nameof(inputStream));

		var objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

		PgpObject? obj = null;
		if (objFactory != null)
			obj = objFactory.NextPgpObject();

		// the first object might be a PGP marker packet.
		PgpEncryptedDataList? encryptedDataList = null;
		PgpObject? message = null;

		if (obj is PgpEncryptedDataList list)
			encryptedDataList = list;
		else if (obj is PgpCompressedData data)
			message = data;
		else
			encryptedDataList = (PgpEncryptedDataList?)objFactory?.NextPgpObject();

		// If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
		if (encryptedDataList == null && message == null)
			throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

		// decrypt
		PgpPrivateKey? privateKey = null;
		PgpPublicKeyEncryptedData? pbe = null;
		if (encryptedDataList != null)
		{
			foreach (PgpPublicKeyEncryptedData pked in encryptedDataList.GetEncryptedDataObjects())
			{
				privateKey = encryptionKeys.FindSecretKey(pked.KeyId);

				if (privateKey != null)
				{
					pbe = pked;
					break;
				}
			}

			if (privateKey == null)
				throw new ArgumentException("Secret key for message not found.");

			PgpObjectFactory? plainFact = null;

			using (Stream clear = pbe!.GetDataStream(privateKey))
			{
				plainFact = new PgpObjectFactory(clear);
			}

			message = plainFact.NextPgpObject();

			if (message is PgpOnePassSignatureList pgpOnePassSignatureList)
			{
				var pgpOnePassSignature = pgpOnePassSignatureList[0];

				var verified = encryptionKeys.PublicKey.KeyId == pgpOnePassSignature.KeyId || encryptionKeys.PublicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(pgpOnePassSignature.KeyId);
				if (verified == false)
					throw new PgpException("Failed to verify file.");

				message = plainFact.NextPgpObject();
			}
			else if (message is not PgpCompressedData)
				throw new PgpException("File was not signed.");
		}

		if (message is PgpCompressedData cData)
		{
			PgpObjectFactory? of = null;

			using (var compDataIn = cData.GetDataStream())
			{
				of = new PgpObjectFactory(compDataIn);
				message = of.NextPgpObject();
			}

			if (message is PgpOnePassSignatureList pgpOnePassSignatureList)
			{
				PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[0];

				var verified = encryptionKeys.PublicKey.KeyId == pgpOnePassSignature.KeyId || encryptionKeys.PublicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(pgpOnePassSignature.KeyId);
				if (verified == false)
					throw new PgpException("Failed to verify file.");

				message = of.NextPgpObject();
				var ld = (PgpLiteralData)message;
				Stream unc = ld.GetInputStream();
				Internal.Streams.PipeAll(unc, outputStream);
			}
			else
			{
				throw new PgpException("File was not signed.");
			}
		}
		else if (message is PgpLiteralData ld)
		{
			//string outFileName = ld.FileName;

			Stream unc = ld.GetInputStream();
			Internal.Streams.PipeAll(unc, outputStream);

			if (pbe!.IsIntegrityProtected())
			{
				if (!pbe.Verify())
				{
					throw new PgpException("Message failed integrity check.");
				}
			}
		}
		else
			throw new PgpException("File was not signed.");

		return outputStream;
	}

	/// <inheritdoc />
	public async Task<Stream> DecryptStreamAndVerifyAsync(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys, CancellationToken cancellationToken = default)
	{
		if (inputStream == null)
			throw new ArgumentNullException(nameof(inputStream));

		if (outputStream == null)
			throw new ArgumentNullException(nameof(outputStream));

		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		if (encryptionKeys.PublicKey == null)
			throw new InvalidOperationException("encryptionKeys.PublicKey == null");

		if (inputStream.Position != 0)
			throw new ArgumentException($"{nameof(inputStream)} should be at start of stream", nameof(inputStream));

		var objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

		PgpObject? obj = null;
		if (objFactory != null)
			obj = objFactory.NextPgpObject();

		// the first object might be a PGP marker packet.
		PgpEncryptedDataList? encryptedDataList = null;
		PgpObject? message = null;

		if (obj is PgpEncryptedDataList list)
			encryptedDataList = list;
		else if (obj is PgpCompressedData data)
			message = data;
		else
			encryptedDataList = (PgpEncryptedDataList?)objFactory?.NextPgpObject();

		// If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
		if (encryptedDataList == null && message == null)
			throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

		// decrypt
		PgpPrivateKey? privateKey = null;
		PgpPublicKeyEncryptedData? pbe = null;
		if (encryptedDataList != null)
		{
			foreach (PgpPublicKeyEncryptedData pked in encryptedDataList.GetEncryptedDataObjects())
			{
				privateKey = encryptionKeys.FindSecretKey(pked.KeyId);

				if (privateKey != null)
				{
					pbe = pked;
					break;
				}
			}

			if (privateKey == null)
				throw new ArgumentException("Secret key for message not found.");

			PgpObjectFactory? plainFact = null;

			using (Stream clear = pbe!.GetDataStream(privateKey))
			{
				plainFact = new PgpObjectFactory(clear);
			}

			message = plainFact.NextPgpObject();

			if (message is PgpOnePassSignatureList pgpOnePassSignatureList)
			{
				PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[0];

				var verified = encryptionKeys.PublicKey.KeyId == pgpOnePassSignature.KeyId || encryptionKeys.PublicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(pgpOnePassSignature.KeyId);
				if (verified == false)
					throw new PgpException("Failed to verify file.");

				message = plainFact.NextPgpObject();
			}
			else if (message is not PgpCompressedData)
				throw new PgpException("File was not signed.");
		}

		if (message is PgpCompressedData cData)
		{
			PgpObjectFactory? of = null;

			using (var compDataIn = cData.GetDataStream())
			{
				of = new PgpObjectFactory(compDataIn);
				message = of.NextPgpObject();
			}

			if (message is PgpOnePassSignatureList pgpOnePassSignatureList)
			{
				PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[0];

				var verified = encryptionKeys.PublicKey.KeyId == pgpOnePassSignature.KeyId || encryptionKeys.PublicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(pgpOnePassSignature.KeyId);
				if (verified == false)
					throw new PgpException("Failed to verify file.");

				message = of.NextPgpObject();
				var ld = (PgpLiteralData)message;
				Stream unc = ld.GetInputStream();
				await Internal.Streams.PipeAllAsync(unc, outputStream, cancellationToken);
			}
			else
			{
				throw new PgpException("File was not signed.");
			}
		}
		else if (message is PgpLiteralData ld)
		{
			//string outFileName = ld.FileName;

			Stream unc = ld.GetInputStream();
			await Internal.Streams.PipeAllAsync(unc, outputStream, cancellationToken);

			if (pbe!.IsIntegrityProtected())
			{
				if (!pbe.Verify())
				{
					throw new PgpException("Message failed integrity check.");
				}
			}
		}
		else
			throw new PgpException("File was not signed.");

		return outputStream;
	}

	/// <inheritdoc />
	public string DecryptArmoredStringAndVerify(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null)
	{
		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		using var inputStream = input.GetStream(encoding);
		using var outputStream = new MemoryStream();
		DecryptStreamAndVerify(inputStream, outputStream, encryptionKeys);
		outputStream.Seek(0, SeekOrigin.Begin);
		return outputStream.GetString(encoding);
	}

	/// <inheritdoc />
	public async Task<string> DecryptArmoredStringAndVerifyAsync(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null, CancellationToken cancellationToken = default)
	{
		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		using var inputStream = await input.GetStreamAsync(encoding);
		using var outputStream = new MemoryStream();
		await DecryptStreamAndVerifyAsync(inputStream, outputStream, encryptionKeys, cancellationToken);
		outputStream.Seek(0, SeekOrigin.Begin);
		return await outputStream.GetStringAsync(encoding);
	}

	/// <inheritdoc />
	public bool VerifyStream(Stream inputStream, IEncryptionKeys encryptionKeys)
	{
		if (inputStream == null)
			throw new ArgumentNullException(nameof(inputStream));

		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		if (encryptionKeys.PublicKey == null)
			throw new InvalidOperationException("encryptionKeys.PublicKey == null");

		if (inputStream.Position != 0)
			throw new ArgumentException($"{nameof(inputStream)} should be at start of stream", nameof(inputStream));

		var publicKey = encryptionKeys.PublicKey;
		bool verified = false;

		var encodedFile = new ArmoredInputStream(inputStream);
		var factory = new PgpObjectFactory(encodedFile);
		var pgpObject = factory.NextPgpObject();

		if (pgpObject is PgpCompressedData pgpCompressedData)
		{
			var pgpCompressedFactory = new PgpObjectFactory(pgpCompressedData.GetDataStream());
			var pgpOnePassSignatureList = (PgpOnePassSignatureList)pgpCompressedFactory.NextPgpObject();
			var pgpOnePassSignature = pgpOnePassSignatureList[0];
			var pgpLiteralData = (PgpLiteralData)factory.NextPgpObject();
			var pgpLiteralStream = pgpLiteralData.GetInputStream();

			// Verify against public key ID and that of any sub keys
			if (publicKey.KeyId == pgpOnePassSignature.KeyId || publicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(pgpOnePassSignature.KeyId))
			{
				foreach (var signature in publicKey.GetSignatures())
				{
					if (!verified)
					{
						pgpOnePassSignature.InitVerify(publicKey);

						int ch;
						while ((ch = pgpLiteralStream.ReadByte()) >= 0)
						{
							pgpOnePassSignature.Update((byte)ch);
						}

						try
						{
							var pgpSignatureList = (PgpSignatureList)factory.NextPgpObject();

							for (int i = 0; i < pgpSignatureList.Count; i++)
							{
								var pgpSignature = pgpSignatureList[i];

								if (pgpOnePassSignature.Verify(pgpSignature))
								{
									verified = true;
									break;
								}
							}
						}
						catch
						{
							verified = false;
							break;
						}
					}
					else
					{
						break;
					}
				}
			}
			else
			{
				verified = false;
			}
		}
		else if (pgpObject is PgpEncryptedDataList encryptedDataList)
		{
			var publicKeyED = Utilities.ExtractPublicKey(encryptedDataList);

			// Verify against public key ID and that of any sub keys
			verified = 
				publicKeyED != null
				&& (publicKey.KeyId == publicKeyED.KeyId
					|| publicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(publicKeyED.KeyId));

			//PgpEncryptedDataList encryptedDataList = (PgpEncryptedDataList)pgpObject;

			//foreach (PgpPublicKeyEncryptedData encryptedData in encryptedDataList.GetEncryptedDataObjects())
			//{
			//    using (encryptedData.GetDataStream(EncryptionKeys.PrivateKey))
			//    {
			//        if (encryptedData.Verify())
			//        {
			//            verified = true;
			//            break;
			//        }
			//    }
			//}
		}
		else if (pgpObject is PgpOnePassSignatureList pgpOnePassSignatureList)
		{
			var pgpOnePassSignature = pgpOnePassSignatureList[0];
			var pgpLiteralData = (PgpLiteralData)factory.NextPgpObject();
			var pgpLiteralStream = pgpLiteralData.GetInputStream();

			// Verify against public key ID and that of any sub keys
			if (publicKey.KeyId == pgpOnePassSignature.KeyId || publicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(pgpOnePassSignature.KeyId))
			{
				pgpOnePassSignature.InitVerify(publicKey);

				int ch;
				while ((ch = pgpLiteralStream.ReadByte()) >= 0)
				{
					pgpOnePassSignature.Update((byte)ch);
				}

				try
				{
					var pgpSignatureList = (PgpSignatureList)factory.NextPgpObject();

					for (int i = 0; i < pgpSignatureList.Count; i++)
					{
						var pgpSignature = pgpSignatureList[i];

						if (pgpOnePassSignature.Verify(pgpSignature))
						{
							verified = true;
							break;
						}
					}
				}
				catch
				{
					verified = false;
				}
			}
			else
			{
				verified = false;
			}
		}
		else if (pgpObject is PgpSignatureList pgpSignatureList)
		{
			var pgpSignature = pgpSignatureList[0];
			var pgpLiteralData = (PgpLiteralData)factory.NextPgpObject();
			var pgpLiteralStream = pgpLiteralData.GetInputStream();

			// Verify against public key ID and that of any sub keys
			if (publicKey.KeyId == pgpSignature.KeyId || publicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(pgpSignature.KeyId))
			{
				foreach (var signature in publicKey.GetSignatures())
				{
					if (!verified)
					{
						pgpSignature.InitVerify(publicKey);

						int ch;
						while ((ch = pgpLiteralStream.ReadByte()) >= 0)
						{
							pgpSignature.Update((byte)ch);
						}

						verified = pgpSignature.Verify();
					}
					else
					{
						break;
					}
				}
			}
			else
			{
				verified = false;
			}
		}
		else
			throw new PgpException("Message is not a encrypted and signed file or simple signed file.");

		return verified;
	}

	/// <inheritdoc />
	public bool VerifyStream2(Stream inputStream, IEncryptionKeys encryptionKeys)
	{
		if (inputStream == null)
			throw new ArgumentNullException(nameof(inputStream));

		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		if (encryptionKeys.PublicKey == null)
			throw new InvalidOperationException("encryptionKeys.PublicKey == null");

		if (inputStream.Position != 0)
			throw new ArgumentException($"{nameof(inputStream)} should be at start of stream", nameof(inputStream));

		var publicKey = encryptionKeys.PublicKey;
		bool verified = false;

		var encodedFile = PgpUtilities.GetDecoderStream(inputStream);
		var factory = new PgpObjectFactory(encodedFile);
		var pgpObject = factory.NextPgpObject();

		if (pgpObject is PgpCompressedData)
		{
			var publicKeyED = Utilities.ExtractPublicKeyEncryptedData(encodedFile);

			// Verify against public key ID and that of any sub keys
			verified = publicKeyED != null
				&& (publicKey.KeyId == publicKeyED.KeyId
					|| publicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(publicKeyED.KeyId));
		}
		else if (pgpObject is PgpEncryptedDataList encryptedDataList)
		{
			var publicKeyED = Utilities.ExtractPublicKey(encryptedDataList);

			// Verify against public key ID and that of any sub keys
			verified = publicKeyED != null
				&& (publicKey.KeyId == publicKeyED.KeyId
					|| publicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(publicKeyED.KeyId));

			//PgpEncryptedDataList encryptedDataList = (PgpEncryptedDataList)pgpObject;

			//foreach (PgpPublicKeyEncryptedData encryptedData in encryptedDataList.GetEncryptedDataObjects())
			//{
			//    encryptedData.GetDataStream(EncryptionKeys.PrivateKey);
			//    if (encryptedData.Verify())
			//    {
			//        verified = true;
			//        break;
			//    }
			//}
		}
		else if (pgpObject is PgpOnePassSignatureList pgpOnePassSignatureList)
		{
			var pgpOnePassSignature = pgpOnePassSignatureList[0];
			var pgpLiteralData = (PgpLiteralData)factory.NextPgpObject();
			var pgpLiteralStream = pgpLiteralData.GetInputStream();

			// Verify against public key ID and that of any sub keys
			if (publicKey.KeyId == pgpOnePassSignature.KeyId || publicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(pgpOnePassSignature.KeyId))
			{
				pgpOnePassSignature.InitVerify(publicKey);

				int ch;
				while ((ch = pgpLiteralStream.ReadByte()) >= 0)
				{
					pgpOnePassSignature.Update((byte)ch);
				}

				try
				{
					var pgpSignatureList = (PgpSignatureList)factory.NextPgpObject();

					for (int i = 0; i < pgpSignatureList.Count; i++)
					{
						var pgpSignature = pgpSignatureList[i];

						if (pgpOnePassSignature.Verify(pgpSignature))
						{
							verified = true;
							break;
						}
					}
				}
				catch
				{
					verified = false;
				}
			}
			else
			{
				verified = false;
			}
		}
		else if (pgpObject is PgpSignatureList pgpSignatureList)
		{
			var pgpSignature = pgpSignatureList[0];
			var pgpLiteralData = (PgpLiteralData)factory.NextPgpObject();
			var pgpLiteralStream = pgpLiteralData.GetInputStream();

			// Verify against public key ID and that of any sub keys
			if (publicKey.KeyId == pgpSignature.KeyId || publicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(pgpSignature.KeyId))
			{
				foreach (var signature in publicKey.GetSignatures())
				{
					if (!verified)
					{
						pgpSignature.InitVerify(publicKey);

						int ch;
						while ((ch = pgpLiteralStream.ReadByte()) >= 0)
						{
							pgpSignature.Update((byte)ch);
						}

						verified = pgpSignature.Verify();
					}
					else
					{
						break;
					}
				}
			}
			else
			{
				verified = false;
			}
		}
		else
			throw new PgpException("Message is not a encrypted and signed file or simple signed file.");

		return verified;
	}

	/// <inheritdoc />
	public bool VerifyArmoredString(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null)
	{
		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		using var inputStream = input.GetStream(encoding);
		using var outputStream = new MemoryStream();
		return VerifyStream(inputStream, encryptionKeys);
	}

	/// <inheritdoc />
	public async Task<bool> VerifyArmoredStringAsync(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null)
	{
		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		using var inputStream = await input.GetStreamAsync(encoding);
		using var outputStream = new MemoryStream();
		return VerifyStream2(inputStream, encryptionKeys);
	}

	/// <inheritdoc />
	public bool VerifyClearStream(Stream inputStream, IEncryptionKeys encryptionKeys)
	{
		if (inputStream == null)
			throw new ArgumentNullException(nameof(inputStream));

		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		if (inputStream.Position != 0)
			throw new ArgumentException($"{nameof(inputStream)} should be at start of stream", nameof(inputStream));

		// https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/openpgp/examples/ClearSignedFileProcessor.cs
		bool verified = false;

		using (var outStream = new MemoryStream())
		{
			var publicKey = encryptionKeys.PublicKey;
			PgpSignature pgpSignature;

			using var armoredInputStream = new ArmoredInputStream(inputStream);
			var lineOut = new MemoryStream();
			var lineSep = LineSeparator;
			var lookAhead = ReadInputLine(lineOut, armoredInputStream);

			// Read past message to signature and store message in stream
			if (lookAhead != -1 && armoredInputStream.IsClearText())
			{
				var line = lineOut.ToArray();
				outStream.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
				outStream.Write(lineSep, 0, lineSep.Length);

				while (lookAhead != -1 && armoredInputStream.IsClearText())
				{
					lookAhead = ReadInputLine(lineOut, lookAhead, armoredInputStream);

					line = lineOut.ToArray();
					outStream.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
					outStream.Write(lineSep, 0, lineSep.Length);
				}
			}
			else if (lookAhead != -1)
			{
				var line = lineOut.ToArray();
				outStream.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
				outStream.Write(lineSep, 0, lineSep.Length);
			}

			// Get public key from correctly positioned stream and initialise for verification
			var pgpObjectFactory = new PgpObjectFactory(armoredInputStream);
			var pgpSignatureList = (PgpSignatureList)pgpObjectFactory.NextPgpObject();
			pgpSignature = pgpSignatureList[0];
			pgpSignature.InitVerify(publicKey);

			// Read through message again and calculate signature
			outStream.Position = 0;
			lookAhead = ReadInputLine(lineOut, outStream);

			ProcessLine(pgpSignature, lineOut.ToArray());

			if (lookAhead != -1)
			{
				do
				{
					lookAhead = ReadInputLine(lineOut, lookAhead, outStream);

					pgpSignature.Update((byte)'\r');
					pgpSignature.Update((byte)'\n');

					ProcessLine(pgpSignature, lineOut.ToArray());
				}
				while (lookAhead != -1);
			}

			verified = pgpSignature.Verify();
		}

		return verified;
	}

	/// <inheritdoc />
	public async Task<bool> VerifyClearStreamAsync(Stream inputStream, IEncryptionKeys encryptionKeys, CancellationToken cancellationToken = default)
	{
		if (inputStream == null)
			throw new ArgumentNullException(nameof(inputStream));

		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		if (inputStream.Position != 0)
			throw new ArgumentException($"{nameof(inputStream)} should be at start of stream", nameof(inputStream));

		// https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/openpgp/examples/ClearSignedFileProcessor.cs
		bool verified = false;

		using (var outStream = new MemoryStream())
		{
			var publicKey = encryptionKeys.PublicKey;
			PgpSignature pgpSignature;

			using var armoredInputStream = new ArmoredInputStream(inputStream);
			var lineOut = new MemoryStream();
			var lineSep = LineSeparator;
			var lookAhead = ReadInputLine(lineOut, armoredInputStream);

			// Read past message to signature and store message in stream
			if (lookAhead != -1 && armoredInputStream.IsClearText())
			{
				var line = lineOut.ToArray();
#if NETSTANDARD2_0 || NETSTANDARD2_1
				await outStream.WriteAsync(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line), cancellationToken);
				await outStream.WriteAsync(lineSep, 0, lineSep.Length, cancellationToken);
#elif NET6_0_OR_GREATER
				await outStream.WriteAsync(line.AsMemory(0, GetLengthWithoutSeparatorOrTrailingWhitespace(line)), cancellationToken);
				await outStream.WriteAsync(lineSep, cancellationToken);
#endif

				while (lookAhead != -1 && armoredInputStream.IsClearText())
				{
					lookAhead = ReadInputLine(lineOut, lookAhead, armoredInputStream);

					line = lineOut.ToArray();
#if NETSTANDARD2_0 || NETSTANDARD2_1
					await outStream.WriteAsync(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line), cancellationToken);
					await outStream.WriteAsync(lineSep, 0, lineSep.Length, cancellationToken);
#elif NET6_0_OR_GREATER
					await outStream.WriteAsync(line.AsMemory(0, GetLengthWithoutSeparatorOrTrailingWhitespace(line)), cancellationToken);
					await outStream.WriteAsync(lineSep, cancellationToken);
#endif
				}
			}
			else if (lookAhead != -1)
			{
				var line = lineOut.ToArray();
#if NETSTANDARD2_0 || NETSTANDARD2_1
				await outStream.WriteAsync(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line), cancellationToken);
				await outStream.WriteAsync(lineSep, 0, lineSep.Length, cancellationToken);
#elif NET6_0_OR_GREATER
				await outStream.WriteAsync(line.AsMemory(0, GetLengthWithoutSeparatorOrTrailingWhitespace(line)), cancellationToken);
				await outStream.WriteAsync(lineSep, cancellationToken);
#endif
			}

			// Get public key from correctly positioned stream and initialise for verification
			var pgpObjectFactory = new PgpObjectFactory(armoredInputStream);
			var pgpSignatureList = (PgpSignatureList)pgpObjectFactory.NextPgpObject();
			pgpSignature = pgpSignatureList[0];
			pgpSignature.InitVerify(publicKey);

			// Read through message again and calculate signature
			outStream.Position = 0;
			lookAhead = ReadInputLine(lineOut, outStream);

			ProcessLine(pgpSignature, lineOut.ToArray());

			if (lookAhead != -1)
			{
				do
				{
					lookAhead = ReadInputLine(lineOut, lookAhead, outStream);

					pgpSignature.Update((byte)'\r');
					pgpSignature.Update((byte)'\n');

					ProcessLine(pgpSignature, lineOut.ToArray());
				}
				while (lookAhead != -1);
			}

			verified = pgpSignature.Verify();
		}

		return verified;
	}

	/// <inheritdoc />
	public bool VerifyClearArmoredString(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null)
	{
		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		using var inputStream = input.GetStream(encoding);
		using var outputStream = new MemoryStream();
		return VerifyClearStream(inputStream, encryptionKeys);
	}

	/// <inheritdoc />
	public async Task<bool> VerifyClearArmoredStringAsync(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null, CancellationToken cancellationToken = default)
	{
		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		using var inputStream = await input.GetStreamAsync(encoding);
		using var outputStream = new MemoryStream();
		return await VerifyClearStreamAsync(inputStream, encryptionKeys, cancellationToken);
	}





	private static int ReadInputLine(MemoryStream streamOut, Stream encodedFile)
	{
		streamOut.SetLength(0);

		int lookAhead = -1;
		int character;

		while (0 <= (character = encodedFile.ReadByte()))
		{
			streamOut.WriteByte((byte)character);
			if (character == '\r' || character == '\n')
			{
				lookAhead = ReadPassedEol(streamOut, character, encodedFile);
				break;
			}
		}

		return lookAhead;
	}

	private static int ReadInputLine(MemoryStream streamOut, int lookAhead, Stream encodedFile)
	{
		streamOut.SetLength(0);

		int character = lookAhead;

		do
		{
			streamOut.WriteByte((byte)character);
			if (character == '\r' || character == '\n')
			{
				lookAhead = ReadPassedEol(streamOut, character, encodedFile);
				break;
			}
		}
		while ((character = encodedFile.ReadByte()) >= 0);

		if (character < 0)
			lookAhead = -1;

		return lookAhead;
	}

	private static int ReadPassedEol(MemoryStream streamOut, int lastCharacter, Stream encodedFile)
	{
		int lookAhead = encodedFile.ReadByte();

		if (lastCharacter == '\r' && lookAhead == '\n')
		{
			streamOut.WriteByte((byte)lookAhead);
			lookAhead = encodedFile.ReadByte();
		}

		return lookAhead;
	}

	private static void ProcessLine(PgpSignature sig, byte[] line)
	{
		// note: trailing white space needs to be removed from the end of
		// each line for signature calculation RFC 4880 Section 7.1
		int length = GetLengthWithoutWhiteSpace(line);
		if (length > 0)
		{
			sig.Update(line, 0, length);
		}
	}

	private static int GetLengthWithoutWhiteSpace(byte[] line)
	{
		int end = line.Length - 1;

		while (end >= 0 && IsWhiteSpace(line[end]))
		{
			end--;
		}

		return end + 1;
	}

	private static bool IsLineEnding(byte b)
	{
		return b == '\r' || b == '\n';
	}
}
