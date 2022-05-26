using System.Text;

namespace Envelope.Cryptography.PGP;

public interface IPGPDecrypt
{
	/// <summary>
	/// PGP decrypt a given stream.
	/// </summary>
	/// <param name="inputStream">PGP encrypted data stream</param>
	/// <param name="outputStream">Output PGP decrypted stream</param>
	/// <param name="encryptionKeys"></param>
	Stream DecryptStream(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys);

	/// <summary>
	/// PGP decrypt a given stream.
	/// </summary>
	/// <param name="inputStream">PGP encrypted data stream</param>
	/// <param name="outputStream">Output PGP decrypted stream</param>
	/// <param name="encryptionKeys"></param>
	/// <param name="cancellationToken"></param>
	Task<Stream> DecryptStreamAsync(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys, CancellationToken cancellationToken = default);

	/// <summary>
	/// PGP decrypt a given string.
	/// </summary>
	/// <param name="input">PGP encrypted string</param>
	/// <param name="encryptionKeys">Encryption keys</param>
	/// <param name="encoding"></param>
	string DecryptArmoredString(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null);

	/// <summary>
	/// PGP decrypt a given string.
	/// </summary>
	/// <param name="input">PGP encrypted string</param>
	/// <param name="encryptionKeys">Encryption keys</param>
	/// <param name="encoding"></param>
	/// <param name="cancellationToken"></param>
	Task<string> DecryptArmoredStringAsync(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null, CancellationToken cancellationToken = default);
}
