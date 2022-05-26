using System.Text;

namespace Envelope.Cryptography.PGP;

public interface IPGPDecryptAndVerify
{
	/// <summary>
	/// PGP decrypt and verify a given stream.
	/// </summary>
	/// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
	/// <param name="outputStream">Output PGP decrypted and verified stream</param>
	/// <param name="encryptionKeys"></param>
	Stream DecryptStreamAndVerify(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys);

	/// <summary>
	/// PGP decrypt and verify a given stream.
	/// </summary>
	/// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
	/// <param name="outputStream">Output PGP decrypted and verified stream</param>
	/// <param name="encryptionKeys"></param>
	/// <param name="cancellationToken"></param>
	Task<Stream> DecryptStreamAndVerifyAsync(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys, CancellationToken cancellationToken = default);

	/// <summary>
	/// PGP decrypt and verify a given string.
	/// </summary>
	/// <param name="input">PGP encrypted string to be decrypted and verified</param>
	/// <param name="encryptionKeys">IEncryptionKeys object containing public key, private key and passphrase</param>
	/// <param name="encoding"></param>
	string DecryptArmoredStringAndVerify(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null);

	/// <summary>
	/// PGP decrypt and verify a given string.
	/// </summary>
	/// <param name="input">PGP encrypted string to be decrypted and verified</param>
	/// <param name="encryptionKeys">IEncryptionKeys object containing public key, private key and passphrase</param>
	/// <param name="encoding"></param>
	/// <param name="cancellationToken"></param>
	Task<string> DecryptArmoredStringAndVerifyAsync(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null, CancellationToken cancellationToken = default);

	/// <summary>
	/// PGP verify a given stream.
	/// </summary>
	/// <param name="inputStream">Plain data stream to be verified</param>
	/// <param name="encryptionKeys"></param>
	bool VerifyStream(Stream inputStream, IEncryptionKeys encryptionKeys);

	/// <summary>
	/// PGP verify a given stream.
	/// </summary>
	/// <param name="inputStream">Plain data stream to be verified</param>
	/// <param name="encryptionKeys"></param>
	bool VerifyStream2(Stream inputStream, IEncryptionKeys encryptionKeys);

	/// <summary>
	/// PGP verify a given string.
	/// </summary>
	/// <param name="input">Plain string to be verified</param>
	/// <param name="encryptionKeys">Encryption keys</param>
	/// <param name="encoding"></param>
	bool VerifyArmoredString(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null);

	/// <summary>
	/// PGP verify a given string.
	/// </summary>
	/// <param name="input">Plain string to be verified</param>
	/// <param name="encryptionKeys">Encryption keys</param>
	/// <param name="encoding"></param>
	Task<bool> VerifyArmoredStringAsync(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null);

	/// <summary>
	/// PGP verify a given clear signed stream.
	/// </summary>
	/// <param name="inputStream">Clear signed stream to be verified</param>
	/// <param name="encryptionKeys"></param>
	bool VerifyClearStream(Stream inputStream, IEncryptionKeys encryptionKeys);

	/// <summary>
	/// PGP verify a given clear signed stream.
	/// </summary>
	/// <param name="inputStream">Clear signed data stream to be verified</param>
	/// <param name="encryptionKeys"></param>
	/// <param name="cancellationToken"></param>
	Task<bool> VerifyClearStreamAsync(Stream inputStream, IEncryptionKeys encryptionKeys, CancellationToken cancellationToken = default);

	/// <summary>
	/// PGP verify a given clear signed string.
	/// </summary>
	/// <param name="input">Clear signed string to be verified</param>
	/// <param name="encryptionKeys">Encryption keys</param>
	/// <param name="encoding"></param>
	bool VerifyClearArmoredString(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null);

	/// <summary>
	/// PGP verify a given clear signed string.
	/// </summary>
	/// <param name="input">Clear signed string to be verified</param>
	/// <param name="encryptionKeys">Encryption keys</param>
	/// <param name="encoding"></param>
	/// <param name="cancellationToken"></param>
	Task<bool> VerifyClearArmoredStringAsync(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null, CancellationToken cancellationToken = default);
}
