using System.Text;

namespace Envelope.Cryptography.PGP;

public interface IPGPClearSign
{
	/// <summary>
	/// Clear sign the file pointed to by unencryptedFileInfo
	/// </summary>
	/// <param name="inputFile">Plain data file to be signed</param>
	/// <param name="outputFile">Output PGP signed file</param>
	/// <param name="encryptionKeys"></param>
	void ClearSignFile(FileInfo inputFile, FileInfo outputFile, IEncryptionKeys encryptionKeys);

	/// <summary>
	/// Clear sign the file pointed to by unencryptedFileInfo
	/// </summary>
	/// <param name="inputFile">Plain data file to be signed</param>
	/// <param name="outputFile">Output PGP signed file</param>
	/// <param name="encryptionKeys"></param>
	/// <param name="cancellationToken"></param>
	Task ClearSignFileAsync(FileInfo inputFile, FileInfo outputFile, IEncryptionKeys encryptionKeys, CancellationToken cancellationToken = default);

	/// <summary>
	/// Clear sign the provided stream
	/// </summary>
	/// <param name="inputStream">Plain data stream to be signed</param>
	/// <param name="outputStream">Output PGP signed stream</param>
	/// <param name="encryptionKeys"></param>
	void ClearSignStream(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys);

	/// <summary>
	/// Clear sign the provided stream
	/// </summary>
	/// <param name="inputStream">Plain data stream to be signed</param>
	/// <param name="outputStream">Output PGP signed stream</param>
	/// <param name="encryptionKeys">Encryption keys</param>
	/// <param name="cancellationToken"></param>
	Task ClearSignStreamAsync(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys, CancellationToken cancellationToken = default);

	/// <summary>
	/// Clear sign the provided string
	/// </summary>
	/// <param name="input">Plain string to be signed</param>
	/// <param name="encryptionKeys">Encryption keys</param>
	/// <param name="encoding"></param>
	string ClearSignArmoredString(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null);

	/// <summary>
	/// Clear sign the provided string
	/// </summary>
	/// <param name="input">Plain string to be signed</param>
	/// <param name="encryptionKeys">Encryption keys</param>
	/// <param name="encoding"></param>
	/// <param name="cancellationToken"></param>
	Task<string> ClearSignArmoredStringAsync(string input, IEncryptionKeys encryptionKeys, Encoding? encoding = null, CancellationToken cancellationToken = default);
}
