using System.Text;

namespace Envelope.Cryptography.PGP;

public interface IPGPSign
{
	/// <summary>
	/// Sign the file pointed to by unencryptedFileInfo
	/// </summary>
	/// <param name="inputFile">Plain data file to be signed</param>
	/// <param name="outputFile">Output PGP signed file</param>
	/// <param name="encryptionKeys"></param>
	/// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
	/// <param name="withIntegrityCheck"></param>
	/// <param name="name">Name of signed file in message, defaults to the input file name</param>
	void SignFile(
		FileInfo inputFile,
		FileInfo outputFile,
		IEncryptionKeys encryptionKeys,
		bool armor = true,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName);

	/// <summary>
	/// Sign the file pointed to by unencryptedFileInfo
	/// </summary>
	/// <param name="inputFile">Plain data file to be signed</param>
	/// <param name="outputFile">Output PGP signed file</param>
	/// <param name="encryptionKeys"></param>
	/// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
	/// <param name="withIntegrityCheck"></param>
	/// <param name="name">Name of signed file in message, defaults to the input file name</param>
	/// <param name="cancellationToken"></param>
	Task SignFileAsync(
		FileInfo inputFile,
		FileInfo outputFile,
		IEncryptionKeys encryptionKeys,
		bool armor = true,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName,
		CancellationToken cancellationToken = default);

	/// <summary>
	/// Sign the stream pointed to by unencryptedFileInfo and
	/// </summary>
	/// <param name="inputStream">Plain data stream to be signed</param>
	/// <param name="outputStream">Output PGP signed stream</param>
	/// <param name="encryptionKeys"></param>
	/// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
	/// <param name="withIntegrityCheck"></param>
	/// <param name="name">Name of signed file in message, defaults to the input file name</param>
	void SignStream(
		Stream inputStream,
		Stream outputStream,
		IEncryptionKeys encryptionKeys,
		bool armor = true,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName);

	/// <summary>
	/// Sign the stream pointed to by unencryptedFileInfo and
	/// </summary>
	/// <param name="inputStream">Plain data stream to be signed</param>
	/// <param name="outputStream">Output PGP signed stream</param>
	/// <param name="encryptionKeys"></param>
	/// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
	/// <param name="withIntegrityCheck"></param>
	/// <param name="name">Name of signed file in message, defaults to the input file name</param>
	/// <param name="cancellationToken"></param>
	Task SignStreamAsync(
		Stream inputStream,
		Stream outputStream,
		IEncryptionKeys encryptionKeys,
		bool armor = true,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName,
		CancellationToken cancellationToken = default);

	/// <summary>
	/// Sign the string
	/// </summary>
	/// <param name="input">Plain string to be signed</param>
	/// <param name="encryptionKeys">Encryption keys</param>
	/// <param name="encoding"></param>
	/// <param name="withIntegrityCheck"></param>
	/// <param name="name">Name of signed file in message, defaults to the input file name</param>
	string SignArmoredString(
		string input,
		IEncryptionKeys encryptionKeys,
		Encoding? encoding = null,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName);

	/// <summary>
	/// Sign the string
	/// </summary>
	/// <param name="input">Plain string to be signed</param>
	/// <param name="encryptionKeys">Encryption keys</param>
	/// <param name="encoding"></param>
	/// <param name="withIntegrityCheck"></param>
	/// <param name="name">Name of signed file in message, defaults to the input file name</param>
	/// <param name="cancellationToken"></param>
	Task<string> SignArmoredStringAsync(
		string input,
		IEncryptionKeys encryptionKeys,
		Encoding? encoding = null,
		bool withIntegrityCheck = true,
		string name = PGPProvider.DefaultFileName,
		CancellationToken cancellationToken = default);
}
