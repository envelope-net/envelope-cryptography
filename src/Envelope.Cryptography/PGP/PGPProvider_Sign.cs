using Org.BouncyCastle.Bcpg;
using System.Text;

namespace Envelope.Cryptography.PGP;

public partial class PGPProvider : IPGPEncrypt, IPGPEncryptAndSign, IPGPSign, IPGPClearSign, IPGPDecrypt, IPGPDecryptAndVerify, IPGPGetRecipients, IPGPGenerateKey
{
	/// <inheritdoc />
	public void SignFile(
		FileInfo inputFile,
		FileInfo outputFile,
		IEncryptionKeys encryptionKeys,
		bool armor = true,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName)
	{
		if (inputFile == null)
			throw new ArgumentNullException(nameof(inputFile));

		if (outputFile == null)
			throw new ArgumentNullException(nameof(outputFile));

		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		if (!inputFile.Exists)
			throw new FileNotFoundException($"Input file {inputFile.FullName} does not exist.");

		if (name == DefaultFileName)
		{
			name = inputFile.Name;
		}

		using var outputStream = outputFile.OpenWrite();
		if (armor)
		{
			using var armoredOutputStream = new ArmoredOutputStream(outputStream);
			OutputSigned(inputFile, armoredOutputStream, encryptionKeys, withIntegrityCheck, name);
		}
		else
			OutputSigned(inputFile, outputStream, encryptionKeys, withIntegrityCheck, name);
	}

	/// <inheritdoc />
	public async Task SignFileAsync(
		FileInfo inputFile,
		FileInfo outputFile,
		IEncryptionKeys encryptionKeys,
		bool armor = true,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName,
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

		if (name == DefaultFileName)
		{
			name = inputFile.Name;
		}

		using var outputStream = outputFile.OpenWrite();
		if (armor)
		{
			using var armoredOutputStream = new ArmoredOutputStream(outputStream);
			await OutputSignedAsync(inputFile, armoredOutputStream, encryptionKeys, withIntegrityCheck, name, cancellationToken);
		}
		else
			await OutputSignedAsync(inputFile, outputStream, encryptionKeys, withIntegrityCheck, name, cancellationToken);
	}

	/// <inheritdoc />
	public void SignStream(
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
			OutputSigned(inputStream, armoredOutputStream, encryptionKeys, withIntegrityCheck, name);
		}
		else
			OutputSigned(inputStream, outputStream, encryptionKeys, withIntegrityCheck, name);
	}

	/// <inheritdoc />
	public async Task SignStreamAsync(
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
			await OutputSignedAsync(inputStream, armoredOutputStream, encryptionKeys, withIntegrityCheck, name, cancellationToken);
		}
		else
			await OutputSignedAsync(inputStream, outputStream, encryptionKeys, withIntegrityCheck, name, cancellationToken);
	}

	/// <inheritdoc />
	public string SignArmoredString(
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
		SignStream(inputStream, outputStream, encryptionKeys, true, withIntegrityCheck, name);
		outputStream.Seek(0, SeekOrigin.Begin);
		return outputStream.GetString(encoding);
	}

	/// <inheritdoc />
	public async Task<string> SignArmoredStringAsync(
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
		await SignStreamAsync(inputStream, outputStream, encryptionKeys, true, withIntegrityCheck, name, cancellationToken);
		outputStream.Seek(0, SeekOrigin.Begin);
		return await outputStream.GetStringAsync(encoding);
	}








	private void OutputSigned(FileInfo inputFile, Stream outputStream, IEncryptionKeys encryptionKeys, bool withIntegrityCheck, string name)
	{
		using var compressedOut = ChainCompressedOut(outputStream);
		var signatureGenerator = InitSignatureGenerator(compressedOut, encryptionKeys);
		using var literalOut = ChainLiteralOut(compressedOut, inputFile);
		using var inputFileStream = inputFile.OpenRead();
		PGPProvider.WriteOutputAndSign(compressedOut, literalOut, inputFileStream, signatureGenerator);
	}

	private void OutputSigned(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys, bool withIntegrityCheck, string name)
	{
		using var compressedOut = ChainCompressedOut(outputStream);
		var signatureGenerator = InitSignatureGenerator(compressedOut, encryptionKeys);
		using var literalOut = ChainLiteralStreamOut(compressedOut, inputStream, name);
		WriteOutputAndSign(compressedOut, literalOut, inputStream, signatureGenerator);
	}

	private async Task OutputSignedAsync(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys, bool withIntegrityCheck, string name, CancellationToken cancellationToken)
	{
		using var compressedOut = ChainCompressedOut(outputStream);
		var signatureGenerator = InitSignatureGenerator(compressedOut, encryptionKeys);
		using var literalOut = ChainLiteralStreamOut(compressedOut, inputStream, name);
		await WriteOutputAndSignAsync(compressedOut, literalOut, inputStream, signatureGenerator, cancellationToken);
	}

	private async Task OutputSignedAsync(FileInfo inputFile, Stream outputStream, IEncryptionKeys encryptionKeys, bool withIntegrityCheck, string name, CancellationToken cancellationToken)
	{
		using Stream compressedOut = ChainCompressedOut(outputStream);
		var signatureGenerator = InitSignatureGenerator(compressedOut, encryptionKeys);
		using Stream literalOut = ChainLiteralOut(compressedOut, inputFile);
		using FileStream inputFileStream = inputFile.OpenRead();
		await WriteOutputAndSignAsync(compressedOut, literalOut, inputFileStream, signatureGenerator, cancellationToken);
	}
}
