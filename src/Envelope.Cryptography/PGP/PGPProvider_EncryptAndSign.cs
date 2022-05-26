using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System.Text;

namespace Envelope.Cryptography.PGP;

public partial class PGPProvider : IPGPEncrypt, IPGPEncryptAndSign, IPGPSign, IPGPClearSign, IPGPDecrypt, IPGPDecryptAndVerify, IPGPGetRecipients, IPGPGenerateKey
{
	/// <inheritdoc />
	public void EncryptFileAndSign(
		FileInfo inputFile,
		FileInfo outputFile,
		IEncryptionKeys encryptionKeys,
		bool armor = true,
		bool withIntegrityCheck = true)
	{
		if (inputFile == null)
			throw new ArgumentNullException(nameof(inputFile));

		if (outputFile == null)
			throw new ArgumentNullException(nameof(outputFile));

		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		if (!inputFile.Exists)
			throw new FileNotFoundException($"Input file {inputFile.FullName} does not exist.");

		using var outputStream = outputFile.OpenWrite();
		if (armor)
		{
			using var armoredOutputStream = new ArmoredOutputStream(outputStream);
			OutputEncrypted(inputFile, armoredOutputStream, encryptionKeys, withIntegrityCheck);
		}
		else
			OutputEncrypted(inputFile, outputStream, encryptionKeys, withIntegrityCheck);
	}

	/// <inheritdoc />
	public async Task EncryptFileAndSignAsync(
		FileInfo inputFile,
		FileInfo outputFile,
		IEncryptionKeys encryptionKeys,
		bool armor = true,
		bool withIntegrityCheck = true,
		CancellationToken cancellationToken = default)
	{
		if (inputFile == null)
			throw new ArgumentNullException(nameof(inputFile));

		if (outputFile == null)
			throw new ArgumentNullException(nameof(outputFile));

		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		if (!inputFile.Exists)
			throw new FileNotFoundException($"Input file {inputFile.FullName} does not exist.");

		using var outputStream = outputFile.OpenWrite();
		if (armor)
		{
			using var armoredOutputStream = new ArmoredOutputStream(outputStream);
			await OutputEncryptedAsync(inputFile, armoredOutputStream, encryptionKeys, withIntegrityCheck, cancellationToken);
		}
		else
			await OutputEncryptedAsync(inputFile, outputStream, encryptionKeys, withIntegrityCheck, cancellationToken);
	}

	/// <inheritdoc />
	public void EncryptStreamAndSign(
		Stream inputStream,
		Stream outputStream,
		IEncryptionKeys encryptionKeys,
		bool armor = true,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName)
	{
		if (inputStream == null)
			throw new ArgumentNullException(nameof(inputStream));

		if (outputStream == null)
			throw new ArgumentNullException(nameof(outputStream));

		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		if (inputStream.Position != 0)
			throw new ArgumentException($"{nameof(inputStream)} should be at start of stream");

		if (name == DefaultFileName && inputStream is FileStream stream)
		{
			string inputFilePath = stream.Name;
			name = Path.GetFileName(inputFilePath);
		}

		if (armor)
		{
			using var armoredOutputStream = new ArmoredOutputStream(outputStream);
			OutputEncrypted(inputStream, armoredOutputStream, encryptionKeys, withIntegrityCheck, name);
		}
		else
			OutputEncrypted(inputStream, outputStream, encryptionKeys, withIntegrityCheck, name);
	}

	/// <inheritdoc />
	public async Task EncryptStreamAndSignAsync(
		Stream inputStream,
		Stream outputStream,
		IEncryptionKeys encryptionKeys,
		bool armor = true,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName,
		CancellationToken cancellationToken = default)
	{
		if (inputStream == null)
			throw new ArgumentNullException(nameof(inputStream));

		if (outputStream == null)
			throw new ArgumentNullException(nameof(outputStream));

		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		if (inputStream.Position != 0)
			throw new ArgumentException($"{nameof(inputStream)} should be at start of stream");

		if (name == DefaultFileName && inputStream is FileStream stream)
		{
			string inputFilePath = stream.Name;
			name = Path.GetFileName(inputFilePath);
		}

		if (armor)
		{
			using var armoredOutputStream = new ArmoredOutputStream(outputStream);
			await OutputEncryptedAsync(inputStream, armoredOutputStream, encryptionKeys, withIntegrityCheck, name, cancellationToken);
		}
		else
			await OutputEncryptedAsync(inputStream, outputStream, encryptionKeys, withIntegrityCheck, name, cancellationToken);
	}

	/// <inheritdoc />
	public string EncryptArmoredStringAndSign(
		string input,
		IEncryptionKeys encryptionKeys,
		Encoding? encoding = null,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName)
	{
		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		using var inputStream = input.GetStream(encoding);
		using var outputStream = new MemoryStream();
		EncryptStreamAndSign(inputStream, outputStream, encryptionKeys, true, withIntegrityCheck, name);
		outputStream.Seek(0, SeekOrigin.Begin);
		return outputStream.GetString(encoding);
	}

	/// <inheritdoc />
	public async Task<string> EncryptArmoredStringAndSignAsync(
		string input,
		IEncryptionKeys encryptionKeys,
		Encoding? encoding = null,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName,
		CancellationToken cancellationToken = default)
	{
		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		using var inputStream = await input.GetStreamAsync(encoding);
		using var outputStream = new MemoryStream();
		await EncryptStreamAndSignAsync(inputStream, outputStream, encryptionKeys, true, withIntegrityCheck, name, cancellationToken);
		outputStream.Seek(0, SeekOrigin.Begin);
		return await outputStream.GetStringAsync(encoding);
	}







	private void OutputEncrypted(FileInfo inputFile, Stream outputStream, IEncryptionKeys encryptionKeys, bool withIntegrityCheck)
	{
		using var encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck, encryptionKeys);
		using var compressedOut = ChainCompressedOut(encryptedOut);
		var signatureGenerator = InitSignatureGenerator(compressedOut, encryptionKeys);
		using var literalOut = ChainLiteralOut(compressedOut, inputFile);
		using var inputFileStream = inputFile.OpenRead();
		PGPProvider.WriteOutputAndSign(compressedOut, literalOut, inputFileStream, signatureGenerator);
	}

	private async Task OutputEncryptedAsync(FileInfo inputFile, Stream outputStream, IEncryptionKeys encryptionKeys, bool withIntegrityCheck, CancellationToken cancellationToken)
	{
		using var encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck, encryptionKeys);
		using var compressedOut = ChainCompressedOut(encryptedOut);
		var signatureGenerator = InitSignatureGenerator(compressedOut, encryptionKeys);
		using var literalOut = ChainLiteralOut(compressedOut, inputFile);
		using var inputFileStream = inputFile.OpenRead();
		await WriteOutputAndSignAsync(compressedOut, literalOut, inputFileStream, signatureGenerator, cancellationToken);
	}

	private void OutputEncrypted(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys, bool withIntegrityCheck, string name)
	{
		using var encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck, encryptionKeys);
		using var compressedOut = ChainCompressedOut(encryptedOut);
		var signatureGenerator = InitSignatureGenerator(compressedOut, encryptionKeys);
		using var literalOut = ChainLiteralStreamOut(compressedOut, inputStream, name);
		WriteOutputAndSign(compressedOut, literalOut, inputStream, signatureGenerator);
	}

	private async Task OutputEncryptedAsync(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys, bool withIntegrityCheck, string name, CancellationToken cancellationToken)
	{
		using var encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck, encryptionKeys);
		using var compressedOut = ChainCompressedOut(encryptedOut);
		var signatureGenerator = InitSignatureGenerator(compressedOut, encryptionKeys);
		using var literalOut = ChainLiteralStreamOut(compressedOut, inputStream, name);
		await WriteOutputAndSignAsync(compressedOut, literalOut, inputStream, signatureGenerator, cancellationToken);
	}

	private Stream ChainEncryptedOut(Stream outputStream, bool withIntegrityCheck, IEncryptionKeys encryptionKeys)
	{
		PgpEncryptedDataGenerator encryptedDataGenerator;
		encryptedDataGenerator = new PgpEncryptedDataGenerator(_options.SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());

		foreach (PgpPublicKey publicKey in encryptionKeys.PublicKeys)
			encryptedDataGenerator.AddMethod(publicKey);

		return encryptedDataGenerator.Open(outputStream, new byte[BufferSize]);
	}

	private Stream ChainCompressedOut(Stream encryptedOut)
	{
		if (_options.CompressionAlgorithm != CompressionAlgorithmTag.Uncompressed)
		{
			var compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
			return compressedDataGenerator.Open(encryptedOut);
		}
		else
			return encryptedOut;
	}

	private PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut, IEncryptionKeys encryptionKeys)
	{
		if (encryptionKeys.SecretKey == null)
			throw new InvalidOperationException("encryptionKeys.SecretKey == null");

		var tag = encryptionKeys.SecretKey.PublicKey.Algorithm;
		var pgpSignatureGenerator = new PgpSignatureGenerator(tag, _options.HashAlgorithm);
		pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, encryptionKeys.PrivateKey);
		foreach (string userId in encryptionKeys.SecretKey.PublicKey.GetUserIds())
		{
			var subPacketGenerator = new PgpSignatureSubpacketGenerator();
			subPacketGenerator.SetSignerUserId(false, userId);
			pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
			// Just the first one!
			break;
		}
		pgpSignatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);
		return pgpSignatureGenerator;
	}

	private Stream ChainLiteralOut(Stream compressedOut, FileInfo file)
	{
		var pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
		return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), file.Name, file.Length, DateTime.UtcNow);
	}

	private Stream ChainLiteralStreamOut(Stream compressedOut, Stream inputStream, string name)
	{
		var pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
		return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), name, inputStream.Length, DateTime.UtcNow);
	}

	private static void WriteOutputAndSign(Stream compressedOut, Stream literalOut, FileStream inputFilePath, PgpSignatureGenerator signatureGenerator)
	{
		int length;
		byte[] buf = new byte[BufferSize];
		while ((length = inputFilePath.Read(buf, 0, buf.Length)) > 0)
		{
			literalOut.Write(buf, 0, length);
			signatureGenerator.Update(buf, 0, length);
		}
		signatureGenerator.Generate().Encode(compressedOut);
	}

	private static async Task WriteOutputAndSignAsync(Stream compressedOut, Stream literalOut, FileStream inputFilePath, PgpSignatureGenerator signatureGenerator, CancellationToken cancellationToken)
	{
		int length;
		byte[] buf = new byte[BufferSize];
#if NETSTANDARD2_0 || NETSTANDARD2_1
		while (0 < (length = await inputFilePath.ReadAsync(buf, 0, buf.Length, cancellationToken)))
		{
			await literalOut.WriteAsync(buf, 0, length, cancellationToken);
			signatureGenerator.Update(buf, 0, length);
		}
#elif NET6_0_OR_GREATER
		while (0 < (length = await inputFilePath.ReadAsync(buf, cancellationToken)))
		{
			await literalOut.WriteAsync(buf.AsMemory(0, length), cancellationToken);
			signatureGenerator.Update(buf, 0, length);
		}
#endif
		signatureGenerator.Generate().Encode(compressedOut);
	}

	private static void WriteOutputAndSign(Stream compressedOut, Stream literalOut, Stream inputStream, PgpSignatureGenerator signatureGenerator)
	{
		int length;
		byte[] buf = new byte[BufferSize];
		while ((length = inputStream.Read(buf, 0, buf.Length)) > 0)
		{
			literalOut.Write(buf, 0, length);
			signatureGenerator.Update(buf, 0, length);
		}
		signatureGenerator.Generate().Encode(compressedOut);
	}

	private static async Task WriteOutputAndSignAsync(Stream compressedOut, Stream literalOut, Stream inputStream, PgpSignatureGenerator signatureGenerator, CancellationToken cancellationToken)
	{
		int length;
		byte[] buf = new byte[BufferSize];
#if NETSTANDARD2_0 || NETSTANDARD2_1
		while (0 < (length = await inputStream.ReadAsync(buf, 0, buf.Length, cancellationToken)))
		{
			await literalOut.WriteAsync(buf, 0, length, cancellationToken);
			signatureGenerator.Update(buf, 0, length);
		}
#elif NET6_0_OR_GREATER
		while (0 < (length = await inputStream.ReadAsync(buf, cancellationToken)))
		{
			await literalOut.WriteAsync(buf.AsMemory(0, length), cancellationToken);
			signatureGenerator.Update(buf, 0, length);
		}
#endif
		signatureGenerator.Generate().Encode(compressedOut);
	}
}
