using System.Text;

namespace Envelope.Cryptography.PGP;

public interface IPGPGetRecipients
{
	/// <summary>
	/// PGP get a recipients keys id of an encrypted stream.
	/// </summary>
	/// <param name="inputStream">PGP encrypted data stream</param>
	/// <returns>Enumerable of public key ids. Value "0" means that the recipient is hidden.</returns>
	IEnumerable<long> GetStreamRecipients(Stream inputStream);

	/// <summary>
	/// PGP get a recipients keys id of an encrypted file.
	/// </summary>
	/// <param name="input">PGP encrypted string</param>
	/// <param name="encoding"></param>
	/// <returns>Enumerable of public key ids. Value "0" means that the recipient is hidden.</returns>
	IEnumerable<long> GetArmoredStringRecipients(string input, Encoding? encoding = null);
}
