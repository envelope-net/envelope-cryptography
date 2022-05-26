using Org.BouncyCastle.Bcpg.OpenPgp;
using System.Text;

namespace Envelope.Cryptography.PGP;

public partial class PGPProvider : IPGPEncrypt, IPGPEncryptAndSign, IPGPSign, IPGPClearSign, IPGPDecrypt, IPGPDecryptAndVerify, IPGPGetRecipients, IPGPGenerateKey
{
	/// <inheritdoc />
	public Stream DecryptStream(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys)
	{
		if (inputStream == null)
			throw new ArgumentNullException(nameof(inputStream));

		if (outputStream == null)
			throw new ArgumentNullException(nameof(outputStream));

		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		if (inputStream.Position != 0)
			throw new ArgumentException($"{nameof(inputStream)} should be at start of stream", nameof(inputStream));

		var objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

		PgpObject? obj = null;
		if (objFactory != null)
			obj = objFactory.NextPgpObject();

		// the first object might be a PGP marker packet.
		PgpEncryptedDataList? enc = null;
		PgpObject? message = null;

		if (obj is PgpEncryptedDataList list)
			enc = list;
		else if (obj is PgpCompressedData data)
			message = data;
		else
			enc = (PgpEncryptedDataList?)objFactory?.NextPgpObject();

		// If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
		if (enc == null && message == null)
			throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

		// decrypt
		PgpPrivateKey? privateKey = null;
		PgpPublicKeyEncryptedData? pbe = null;
		if (enc != null)
		{
			foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
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

			using (var clear = pbe!.GetDataStream(privateKey))
			{
				plainFact = new PgpObjectFactory(clear);
			}

			message = plainFact.NextPgpObject();

			if (message is PgpOnePassSignatureList)
			{
				message = plainFact.NextPgpObject();
			}
		}

		if (message is PgpCompressedData cData)
		{
			PgpObjectFactory? of = null;

			using (var compDataIn = cData.GetDataStream())
			{
				of = new PgpObjectFactory(compDataIn);
				message = of.NextPgpObject();
			}

			if (message is PgpOnePassSignatureList)
			{
				message = of.NextPgpObject();
				var ld = (PgpLiteralData)message;
				var unc = ld.GetInputStream();
				Internal.Streams.PipeAll(unc, outputStream);
			}
			else
			{
				var ld = (PgpLiteralData)message;
				Stream unc = ld.GetInputStream();
				Internal.Streams.PipeAll(unc, outputStream);
			}
		}
		else if (message is PgpLiteralData ld)
		{
			//var outFileName = ld.FileName;

			var unc = ld.GetInputStream();
			Internal.Streams.PipeAll(unc, outputStream);

			if (pbe!.IsIntegrityProtected())
			{
				if (!pbe.Verify())
				{
					throw new PgpException("Message failed integrity check.");
				}
			}
		}
		else if (message is PgpOnePassSignatureList)
			throw new PgpException("Encrypted message contains a signed message - not literal data.");
		else
			throw new PgpException("Message is not a simple encrypted file.");

		return outputStream;
	}

	/// <inheritdoc />
	public async Task<Stream> DecryptStreamAsync(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys, CancellationToken cancellationToken = default)
	{
		if (inputStream == null)
			throw new ArgumentNullException(nameof(inputStream));

		if (outputStream == null)
			throw new ArgumentNullException(nameof(outputStream));

		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		if (inputStream.Position != 0)
			throw new ArgumentException($"{nameof(inputStream)} should be at start of stream", nameof(inputStream));

		var objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

		PgpObject? obj = null;
		if (objFactory != null)
			obj = objFactory.NextPgpObject();

		// the first object might be a PGP marker packet.
		PgpEncryptedDataList? enc = null;
		PgpObject? message = null;

		if (obj is PgpEncryptedDataList list)
			enc = list;
		else if (obj is PgpCompressedData data)
			message = data;
		else
			enc = (PgpEncryptedDataList?)objFactory?.NextPgpObject();

		// If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
		if (enc == null && message == null)
			throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

		// decrypt
		PgpPrivateKey? privateKey = null;
		PgpPublicKeyEncryptedData? pbe = null;
		if (enc != null)
		{
			foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
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

			using (var clear = pbe!.GetDataStream(privateKey))
			{
				plainFact = new PgpObjectFactory(clear);
			}

			message = plainFact.NextPgpObject();

			if (message is PgpOnePassSignatureList)
			{
				message = plainFact.NextPgpObject();
			}
		}

		if (message is PgpCompressedData cData)
		{
			PgpObjectFactory? of = null;

			using (var compDataIn = cData.GetDataStream())
			{
				of = new PgpObjectFactory(compDataIn);
				message = of.NextPgpObject();
			}

			if (message is PgpOnePassSignatureList)
			{
				message = of.NextPgpObject();
				var ld = (PgpLiteralData)message;
				Stream unc = ld.GetInputStream();
				await Internal.Streams.PipeAllAsync(unc, outputStream, cancellationToken);
			}
			else
			{
				var ld = (PgpLiteralData)message;
				Stream unc = ld.GetInputStream();
				await Internal.Streams.PipeAllAsync(unc, outputStream, cancellationToken);
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
		else if (message is PgpOnePassSignatureList)
			throw new PgpException("Encrypted message contains a signed message - not literal data.");
		else
			throw new PgpException("Message is not a simple encrypted file.");

		return outputStream;
	}

	/// <inheritdoc />
	public string DecryptArmoredString(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null)
	{
		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		using var inputStream = input.GetStream(encoding);
		using var outputStream = new MemoryStream();
		DecryptStream(inputStream, outputStream, encryptionKeys);
		outputStream.Seek(0, SeekOrigin.Begin);
		return outputStream.GetString(encoding);
	}

	/// <inheritdoc />
	public async Task<string> DecryptArmoredStringAsync(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null, CancellationToken cancellationToken = default)
	{
		if (encryptionKeys == null)
			throw new ArgumentNullException(nameof(encryptionKeys));

		using var inputStream = await input.GetStreamAsync(encoding);
		using var outputStream = new MemoryStream();
		await DecryptStreamAsync(inputStream, outputStream, encryptionKeys, cancellationToken);
		outputStream.Seek(0, SeekOrigin.Begin);
		return await outputStream.GetStringAsync(encoding);
	}
}
