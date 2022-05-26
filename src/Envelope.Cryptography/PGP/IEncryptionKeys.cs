using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Envelope.Cryptography.PGP;

public interface IEncryptionKeys
{
	PgpPublicKey? PublicKey { get; }
	IEnumerable<PgpPublicKey> PublicKeys { get; }
	PgpPrivateKey? PrivateKey { get; }
	PgpSecretKey? SecretKey { get; }
	PgpSecretKeyRingBundle? SecretKeys { get; }

	PgpPrivateKey? FindSecretKey(long keyId);
}
