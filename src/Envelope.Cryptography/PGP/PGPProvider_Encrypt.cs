using Envelope.Cryptography.PGP.Internal;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System.Text;

namespace Envelope.Cryptography.PGP;

public partial class PGPProvider : IPGPEncrypt, IPGPEncryptAndSign, IPGPSign, IPGPClearSign, IPGPDecrypt, IPGPDecryptAndVerify, IPGPGetRecipients, IPGPGenerateKey
{
	/// <inheritdoc />
	public void EncryptStream(
		Stream inputStream,
		Stream outputStream,
		IEncryptionKeys encryptionKeys,
		bool armor = true,
		bool withIntegrityCheck = true,
		string name = DefaultFileName)
	{
		if (inputStream == null)
			throw new ArgumentNullException(nameof(inputStream));

		if (outputStream == null)
			throw new ArgumentNullException(nameof(outputStream));

		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		if (inputStream.Position != 0)
			throw new ArgumentException($"{nameof(inputStream)} should be at start of stream", nameof(inputStream));

		if (name == DefaultFileName && inputStream is FileStream stream)
		{
			string inputFilePath = stream.Name;
			name = Path.GetFileName(inputFilePath);
		}

		if (armor)
			outputStream = new ArmoredOutputStream(outputStream);

		var pk = new PgpEncryptedDataGenerator(_options.SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());

		foreach (var publicKey in encryptionKeys.PublicKeys)
			pk.AddMethod(publicKey);

		var @out = pk.Open(outputStream, new byte[1 << 16]);

		if (_options.CompressionAlgorithm != CompressionAlgorithmTag.Uncompressed)
		{
			var comData = new PgpCompressedDataGenerator(_options.CompressionAlgorithm);
			Utilities.WriteStreamToLiteralData(comData.Open(@out), FileTypeToChar(), inputStream, name);
			comData.Close();
		}
		else
			Utilities.WriteStreamToLiteralData(@out, FileTypeToChar(), inputStream, name);

		@out.Close();

		if (armor)
			outputStream.Close();
	}

	/// <inheritdoc />
	public async Task EncryptStreamAsync(
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
			throw new ArgumentException($"{nameof(inputStream)} should be at start of stream", nameof(inputStream));

		if (name == DefaultFileName && inputStream is FileStream stream)
		{
			string inputFilePath = stream.Name;
			name = Path.GetFileName(inputFilePath);
		}

		if (armor)
			outputStream = new ArmoredOutputStream(outputStream);

		var pk = new PgpEncryptedDataGenerator(_options.SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());

		foreach (var publicKey in encryptionKeys.PublicKeys)
			pk.AddMethod(publicKey);

		var @out = pk.Open(outputStream, new byte[1 << 16]);

		if (_options.CompressionAlgorithm != CompressionAlgorithmTag.Uncompressed)
		{
			var comData = new PgpCompressedDataGenerator(_options.CompressionAlgorithm);
			await Utilities.WriteStreamToLiteralDataAsync(comData.Open(@out), FileTypeToChar(), inputStream, name, cancellationToken);
			comData.Close();
		}
		else
			await Utilities.WriteStreamToLiteralDataAsync(@out, FileTypeToChar(), inputStream, name, cancellationToken);

		@out.Close();

		if (armor)
			outputStream.Close();
	}

	/// <inheritdoc />
	public string EncryptArmoredString(
		string input,
		IEncryptionKeys encryptionKeys,
		Encoding? encoding = null,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName)
	{
		using var inputStream = input.GetStream(encoding);
		using var outputStream = new MemoryStream();
		EncryptStream(inputStream, outputStream, encryptionKeys, true, withIntegrityCheck, name);
		outputStream.Seek(0, SeekOrigin.Begin);
		return outputStream.GetString(encoding);
	}

	/// <inheritdoc />
	public async Task<string> EncryptArmoredStringAsync(
		string input,
		IEncryptionKeys encryptionKeys,
		Encoding? encoding = null,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName,
		CancellationToken cancellationToken = default)
	{
		using var inputStream = await input.GetStreamAsync(encoding);
		using var outputStream = new MemoryStream();
		await EncryptStreamAsync(inputStream, outputStream, encryptionKeys, true, withIntegrityCheck, name, cancellationToken);
		outputStream.Seek(0, SeekOrigin.Begin);
		return await outputStream.GetStringAsync(encoding);
	}
}
