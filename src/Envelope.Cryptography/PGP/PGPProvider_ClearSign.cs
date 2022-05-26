using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.Text;

namespace Envelope.Cryptography.PGP;

public partial class PGPProvider : IPGPEncrypt, IPGPEncryptAndSign, IPGPSign, IPGPClearSign, IPGPDecrypt, IPGPDecryptAndVerify, IPGPGetRecipients, IPGPGenerateKey
{
	// https://github.com/bcgit/bc-csharp/blob/f18a2dbbc2c1b4277e24a2e51f09cac02eedf1f5/crypto/test/src/openpgp/examples/ClearSignedFileProcessor.cs

	/// <inheritdoc />
	public void ClearSignFile(FileInfo inputFile, FileInfo outputFile, IEncryptionKeys encryptionKeys)
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
		OutputClearSigned(inputFile, outputStream, encryptionKeys);
	}

	/// <inheritdoc />
	public async Task ClearSignFileAsync(FileInfo inputFile, FileInfo outputFile, IEncryptionKeys encryptionKeys, CancellationToken cancellationToken = default)
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
		await OutputClearSignedAsync(inputFile, outputStream, encryptionKeys, cancellationToken);
	}

	/// <inheritdoc />
	public void ClearSignStream(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys)
	{
		if (inputStream == null)
			throw new ArgumentNullException(nameof(inputStream));

		if (outputStream == null)
			throw new ArgumentNullException(nameof(outputStream));

		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		if (inputStream.Position != 0)
			throw new ArgumentException($"{nameof(inputStream)} should be at start of stream");

		OutputClearSigned(inputStream, outputStream, encryptionKeys);
	}

	/// <inheritdoc />
	public async Task ClearSignStreamAsync(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys, CancellationToken cancellationToken = default)
	{
		if (inputStream == null)
			throw new ArgumentNullException(nameof(inputStream));

		if (outputStream == null)
			throw new ArgumentNullException(nameof(outputStream));

		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		if (inputStream.Position != 0)
			throw new ArgumentException($"{nameof(inputStream)} should be at start of stream");

		await OutputClearSignedAsync(inputStream, outputStream, encryptionKeys, cancellationToken);
	}

	/// <inheritdoc />
	public string ClearSignArmoredString(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null)
	{
		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		using var inputStream = input.GetStream(encoding);
		using var outputStream = new MemoryStream();
		ClearSignStream(inputStream, outputStream, encryptionKeys);
		outputStream.Seek(0, SeekOrigin.Begin);
		return outputStream.GetString(encoding);
	}

	/// <inheritdoc />
	public async Task<string> ClearSignArmoredStringAsync(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null, CancellationToken cancellationToken = default)
	{
		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		using var inputStream = await input.GetStreamAsync(encoding);
		using var outputStream = new MemoryStream();
		await ClearSignStreamAsync(inputStream, outputStream, encryptionKeys, cancellationToken);
		outputStream.Seek(0, SeekOrigin.Begin);
		return await outputStream.GetStringAsync(encoding);
	}




	private void OutputClearSigned(FileInfo inputFile, Stream outputStream, IEncryptionKeys encryptionKeys)
	{
		using var inputFileStream = inputFile.OpenRead();
		OutputClearSigned(inputFileStream, outputStream, encryptionKeys);
	}

	private void OutputClearSigned(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys)
	{
		using var streamReader = new StreamReader(inputStream);
		using var armoredOutputStream = new ArmoredOutputStream(outputStream);
		var pgpSignatureGenerator = InitClearSignatureGenerator(armoredOutputStream, encryptionKeys);

		while (0 <= streamReader.Peek())
		{
			var line = streamReader.ReadLine();
			var lineByteArray = Encoding.ASCII.GetBytes(line!);
			// Does the line end with whitespace?
			// Trailing white space needs to be removed from the end of the document for a valid signature RFC 4880 Section 7.1
			var cleanLine = line!.TrimEnd();
			var cleanLineByteArray = Encoding.ASCII.GetBytes(cleanLine);

			pgpSignatureGenerator.Update(cleanLineByteArray, 0, cleanLineByteArray.Length);
			armoredOutputStream.Write(lineByteArray, 0, lineByteArray.Length);

			// Add a line break back to the stream
			armoredOutputStream.Write((byte)'\r');
			armoredOutputStream.Write((byte)'\n');

			// Update signature with line breaks unless we're on the last line
			if (streamReader.Peek() >= 0)
			{
				pgpSignatureGenerator.Update((byte)'\r');
				pgpSignatureGenerator.Update((byte)'\n');
			}
		}

		armoredOutputStream.EndClearText();

		var bcpgOutputStream = new BcpgOutputStream(armoredOutputStream);
		pgpSignatureGenerator.Generate().Encode(bcpgOutputStream);
	}

	private async Task OutputClearSignedAsync(FileInfo inputFile, Stream outputStream, IEncryptionKeys encryptionKeys, CancellationToken cancellationToken)
	{
		using var inputFileStream = inputFile.OpenRead();
		await OutputClearSignedAsync(inputFileStream, outputStream, encryptionKeys, cancellationToken);
	}

	private async Task OutputClearSignedAsync(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys, CancellationToken cancellationToken)
	{
		using var streamReader = new StreamReader(inputStream);
		using var armoredOutputStream = new ArmoredOutputStream(outputStream);
		var pgpSignatureGenerator = InitClearSignatureGenerator(armoredOutputStream, encryptionKeys);

		while (0 <= streamReader.Peek())
		{
			var line = await streamReader.ReadLineAsync();
			var lineByteArray = Encoding.ASCII.GetBytes(line!);
			// Does the line end with whitespace?
			// Trailing white space needs to be removed from the end of the document for a valid signature RFC 4880 Section 7.1
			var cleanLine = line!.TrimEnd();
			var cleanLineByteArray = Encoding.ASCII.GetBytes(cleanLine);

			pgpSignatureGenerator.Update(cleanLineByteArray, 0, cleanLineByteArray.Length);
#if NETSTANDARD2_0 || NETSTANDARD2_1
			await armoredOutputStream.WriteAsync(lineByteArray, 0, lineByteArray.Length, cancellationToken);
#elif NET6_0_OR_GREATER
			await armoredOutputStream.WriteAsync(lineByteArray, cancellationToken);
#endif

			// Add a line break back to the stream
			armoredOutputStream.Write((byte)'\r');
			armoredOutputStream.Write((byte)'\n');

			// Update signature with line breaks unless we're on the last line
			if (streamReader.Peek() >= 0)
			{
				pgpSignatureGenerator.Update((byte)'\r');
				pgpSignatureGenerator.Update((byte)'\n');
			}
		}

		armoredOutputStream.EndClearText();

		var bcpgOutputStream = new BcpgOutputStream(armoredOutputStream);
		pgpSignatureGenerator.Generate().Encode(bcpgOutputStream);
	}

	private PgpSignatureGenerator InitClearSignatureGenerator(ArmoredOutputStream armoredOutputStream, IEncryptionKeys encryptionKeys)
	{
		if (encryptionKeys.SecretKey == null)
			throw new InvalidOperationException("encryptionKeys.SecretKey == null");

		var tag = encryptionKeys.SecretKey.PublicKey.Algorithm;
		var pgpSignatureGenerator = new PgpSignatureGenerator(tag, _options.HashAlgorithm);
		pgpSignatureGenerator.InitSign(PgpSignature.CanonicalTextDocument, encryptionKeys.PrivateKey);
		armoredOutputStream.BeginClearText(_options.HashAlgorithm);
		foreach (string userId in encryptionKeys.SecretKey.PublicKey.GetUserIds())
		{
			var subPacketGenerator = new PgpSignatureSubpacketGenerator();
			subPacketGenerator.SetSignerUserId(false, userId);
			pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
			// Just the first one!
			break;
		}
		return pgpSignatureGenerator;
	}
}
