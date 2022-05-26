using Envelope.Validation;
using Org.BouncyCastle.Bcpg;

namespace Envelope.Cryptography.PGP;

public interface IPGPOptions : IValidable
{
	CompressionAlgorithmTag CompressionAlgorithm { get; set; }

	SymmetricKeyAlgorithmTag SymmetricKeyAlgorithm { get; set; }

	int PgpSignatureType { get; set; }

	PublicKeyAlgorithmTag PublicKeyAlgorithm { get; set; }

	PGPFileType FileType { get; set; }

	HashAlgorithmTag HashAlgorithm { get; set; }
}
