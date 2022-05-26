using System.Text;

namespace Envelope.Cryptography.PGP;

public interface IPGPEncrypt
{
	/// <summary>
	/// PGP Encrypt the stream.
	/// </summary>
	/// <param name="inputStream">Plain data stream to be encrypted</param>
	/// <param name="outputStream">Output PGP encrypted stream</param>
	/// <param name="encryptionKeys">IEncryptionKeys object containing public keys</param>
	/// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
	/// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
	/// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
	void EncryptStream(
		Stream inputStream,
		Stream outputStream,
		IEncryptionKeys encryptionKeys,
		bool armor = true,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName);

	/// <summary>
	/// PGP Encrypt the stream.
	/// </summary>
	/// <param name="inputStream">Plain data stream to be encrypted</param>
	/// <param name="outputStream">Output PGP encrypted stream</param>
	/// <param name="encryptionKeys">IEncryptionKeys object containing public keys</param>
	/// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
	/// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
	/// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
	/// <param name="cancellationToken">cancellationToken</param>
	Task EncryptStreamAsync(
		Stream inputStream,
		Stream outputStream,
		IEncryptionKeys encryptionKeys,
		bool armor = true,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName,
		CancellationToken cancellationToken = default);

	/// <summary>
	/// PGP Encrypt the string.
	/// </summary>
	/// <param name="input">Plain string to be encrypted</param>
	/// <param name="encryptionKeys">IEncryptionKeys object containing public keys</param>
	/// <param name="encoding"></param>
	/// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
	/// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
	string EncryptArmoredString(
		string input,
		IEncryptionKeys encryptionKeys,
		Encoding? encoding = null,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName);

	/// <summary>
	/// PGP Encrypt the string.
	/// </summary>
	/// <param name="input">Plain string to be encrypted</param>
	/// <param name="encryptionKeys">IEncryptionKeys object containing public keys</param>
	/// <param name="encoding"></param>
	/// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
	/// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
	/// <param name="cancellationToken">cancellationToken</param>
	Task<string> EncryptArmoredStringAsync(
		string input,
		IEncryptionKeys encryptionKeys,
		Encoding? encoding = null,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName,
		CancellationToken cancellationToken = default);
}
