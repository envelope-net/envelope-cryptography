namespace Envelope.Cryptography.PGP;

public interface IPGPGenerateKey
{
	public void GenerateKey(
		string publicKeyFilePath,
		string privateKeyFilePath,
		string? username = null,
		string? password = null,
		int strength = 1024,
		int certainty = 8,
		bool emitVersion = true);

	public void GenerateKey(
		Stream publicKeyStream,
		Stream privateKeyStream,
		string? username = null,
		string? password = null,
		int strength = 1024,
		int certainty = 8,
		bool armor = true,
		bool emitVersion = true);
}
