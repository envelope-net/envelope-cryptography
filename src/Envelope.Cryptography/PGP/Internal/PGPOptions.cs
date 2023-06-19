using Envelope.Validation;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Envelope.Cryptography.PGP.Internal;

public class PGPOptions : IPGPOptions, IValidable
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

	public List<IValidationMessage>? Validate(
		string? propertyPrefix = null,
		ValidationBuilder? validationBuilder = null,
		Dictionary<string, object>? globalValidationContext = null,
		Dictionary<string, object>? customValidationContext = null)
	{
		validationBuilder ??= new ValidationBuilder();
		validationBuilder.SetValidationMessages(propertyPrefix, globalValidationContext)
			.IfNull(EncryptionKeys)
			;

		return validationBuilder.Build();
	}
}
