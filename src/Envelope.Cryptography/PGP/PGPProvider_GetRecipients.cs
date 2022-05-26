using Org.BouncyCastle.Bcpg.OpenPgp;
using System.Text;

namespace Envelope.Cryptography.PGP;

public partial class PGPProvider : IPGPEncrypt, IPGPEncryptAndSign, IPGPSign, IPGPClearSign, IPGPDecrypt, IPGPDecryptAndVerify, IPGPGetRecipients, IPGPGenerateKey
{
	/// <inheritdoc />
	public IEnumerable<long> GetStreamRecipients(Stream inputStream)
	{
		if (inputStream == null)
			throw new ArgumentException("InputStream");

		var objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

		PgpObject? obj = null;
		if (objFactory != null)
			obj = objFactory.NextPgpObject();

		// the first object might be a PGP marker packet.
		PgpEncryptedDataList? enc = null;

		if (obj is PgpEncryptedDataList list)
			enc = list;
		else
			enc = (PgpEncryptedDataList?)objFactory?.NextPgpObject();

		// If enc is null at this point, we failed to detect the contents of the encrypted stream.
		if (enc == null)
			throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

		// Return keys id
		return enc.GetEncryptedDataObjects().OfType<PgpPublicKeyEncryptedData>().Select(k => k.KeyId);
	}

	/// <inheritdoc />
	public IEnumerable<long> GetArmoredStringRecipients(string input, Encoding? encoding = null)
	{
		if (string.IsNullOrEmpty(input))
			throw new ArgumentException("Input");

		using Stream inputStream = input.GetStream(encoding);
		return GetStreamRecipients(inputStream);
	}
}
