using Envelope.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.Text;

namespace Envelope.Cryptography.PGP.Internal;

public class PGPOptions : IPGPOptions
{
	public CompressionAlgorithmTag CompressionAlgorithm { get; set; } = CompressionAlgorithmTag.Uncompressed;

	public SymmetricKeyAlgorithmTag SymmetricKeyAlgorithm { get; set; } = SymmetricKeyAlgorithmTag.TripleDes;

	public int PgpSignatureType { get; set; } = PgpSignature.DefaultCertification;

	public PublicKeyAlgorithmTag PublicKeyAlgorithm { get; set; } = PublicKeyAlgorithmTag.RsaGeneral;

	public PGPFileType FileType { get; set; } = PGPFileType.Binary;

	public HashAlgorithmTag HashAlgorithm { get; set; } = HashAlgorithmTag.Sha1;

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
	public IEncryptionKeys EncryptionKeys { get; set; }
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.

	public StringBuilder? Validate(string? propertyPrefix = null, StringBuilder? parentErrorBuffer = null, Dictionary<string, object>? validationContext = null)
	{
		if (EncryptionKeys == null)
		{
			if (parentErrorBuffer == null)
				parentErrorBuffer = new StringBuilder();

			parentErrorBuffer.AppendLine($"{StringHelper.ConcatIfNotNullOrEmpty(propertyPrefix, ".", nameof(EncryptionKeys))} == null");
		}

		return parentErrorBuffer;
	}
}
