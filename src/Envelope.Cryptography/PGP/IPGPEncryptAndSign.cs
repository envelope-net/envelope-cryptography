using System.Text;

namespace Envelope.Cryptography.PGP;

public interface IPGPEncryptAndSign
{
	/// <summary>
	/// Encrypt and sign the file pointed to by unencryptedFileInfo and
	/// </summary>
	/// <param name="inputFile"></param>
	/// <param name="outputFile"></param>
	/// <param name="encryptionKeys"></param>
	/// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
	/// <param name="withIntegrityCheck"></param>
	void EncryptFileAndSign(
		FileInfo inputFile,
		FileInfo outputFile,
		IEncryptionKeys encryptionKeys,
		bool armor = true,
		bool withIntegrityCheck = true);

	/// <summary>
	/// Encrypt and sign the file pointed to by unencryptedFileInfo and
	/// </summary>
	/// <param name="inputFile"></param>
	/// <param name="outputFile"></param>
	/// <param name="encryptionKeys"></param>
	/// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
	/// <param name="withIntegrityCheck"></param>
	/// <param name="cancellationToken"></param>
	Task EncryptFileAndSignAsync(
		FileInfo inputFile,
		FileInfo outputFile,
		IEncryptionKeys encryptionKeys,
		bool armor = true,
		bool withIntegrityCheck = true,
		CancellationToken cancellationToken = default);

	/// <summary>
	/// Encrypt and sign the stream pointed to by unencryptedFileInfo and
	/// </summary>
	/// <param name="inputStream">Plain data stream to be encrypted and signed</param>
	/// <param name="outputStream">Output PGP encrypted and signed stream</param>
	/// <param name="encryptionKeys"></param>
	/// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
	/// <param name="withIntegrityCheck"></param>
	/// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
	void EncryptStreamAndSign(
		Stream inputStream,
		Stream outputStream,
		IEncryptionKeys encryptionKeys,
		bool armor = true,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName);

	/// <summary>
	/// Encrypt and sign the stream pointed to by unencryptedFileInfo and
	/// </summary>
	/// <param name="inputStream">Plain data stream to be encrypted and signed</param>
	/// <param name="outputStream">Output PGP encrypted and signed stream</param>
	/// <param name="encryptionKeys"></param>
	/// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
	/// <param name="withIntegrityCheck"></param>
	/// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
	/// <param name="cancellationToken"></param>
	Task EncryptStreamAndSignAsync(
		Stream inputStream,
		Stream outputStream,
		IEncryptionKeys encryptionKeys,
		bool armor = true,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName,
		CancellationToken cancellationToken = default);

	/// <summary>
	/// Encrypt and sign the string
	/// </summary>
	/// <param name="input">Plain string to be encrypted and signed</param>
	/// <param name="encryptionKeys"></param>
	/// <param name="encoding"></param>
	/// <param name="withIntegrityCheck"></param>
	/// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
	string EncryptArmoredStringAndSign(
		string input,
		IEncryptionKeys encryptionKeys,
		Encoding? encoding = null,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName);

	/// <summary>
	/// Encrypt and sign the string
	/// </summary>
	/// <param name="input">Plain string to be encrypted and signed</param>
	/// <param name="encryptionKeys">Encryption keys</param>
	/// <param name="encoding"></param>
	/// <param name="withIntegrityCheck"></param>
	/// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
	/// <param name="cancellationToken"></param>
	Task<string> EncryptArmoredStringAndSignAsync(
		string input,
		IEncryptionKeys encryptionKeys,
		Encoding? encoding = null,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName,
		CancellationToken cancellationToken = default);
}
