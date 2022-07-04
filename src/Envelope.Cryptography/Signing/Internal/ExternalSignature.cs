using iText.Signatures;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Envelope.Cryptography.Signing.Internal;

internal class ExternalSignature : IExternalSignature
{
	private readonly X509Certificate2 _certificate;

	public ExternalSignature(X509Certificate2 certificate)
	{
		_certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
	}

	public string GetEncryptionAlgorithm()
		=> "RSA";

	public string GetHashAlgorithm()
		=> DigestAlgorithms.SHA256;

	public byte[] Sign(byte[] message)
	{
		byte[] hash;
		using (var sha256 = SHA256.Create())
		{
			hash = sha256.ComputeHash(message);
		}

		var rsa = _certificate.GetRSAPrivateKey();
		if (rsa == null)
			throw new InvalidOperationException($"No private key");

		var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
		rsaFormatter.SetHashAlgorithm("SHA256");
		return rsaFormatter.CreateSignature(hash);
	}
}