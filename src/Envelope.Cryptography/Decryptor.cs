using System.Security.Cryptography;

namespace Envelope.Cryptography;

public class Decryptor
{
	/// <summary>
	/// 
	/// </summary>
	/// <param name="encryptedData"></param>
	/// <param name="aesKey">32 bytes length key</param>
	public static byte[] AESDecrypt(byte[] encryptedData, byte[] aesKey)
	{
		if (encryptedData == null)
			throw new ArgumentNullException(nameof(encryptedData));

		var buffer = new byte[encryptedData.Length];

		using var aes = Aes.Create();

		if (aes == null)
			throw new InvalidOperationException($"{nameof(aes)} == null");

		aes.Key = aesKey ?? throw new ArgumentNullException(nameof(aesKey));

		var iv = new byte[aes.IV.Length];
		var ciphertext = new byte[buffer.Length - iv.Length];

		Array.ConstrainedCopy(encryptedData, 0, iv, 0, iv.Length);
		Array.ConstrainedCopy(encryptedData, iv.Length, ciphertext, 0, ciphertext.Length);

		aes.IV = iv;

		using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
		using var resultStream = new MemoryStream();
		using (var aesStream = new CryptoStream(resultStream, decryptor, CryptoStreamMode.Write))
		using (var plainStream = new MemoryStream(ciphertext))
		{
			plainStream.CopyTo(aesStream);
		}

		return resultStream.ToArray();
	}

	/// <summary>
	/// 
	/// </summary>
	/// <param name="encryptedData"></param>
	/// <param name="aesKey">32 bytes length key</param>
	public static MemoryStream AESDecryptAsStream(byte[] encryptedData, byte[] aesKey)
	{
		if (encryptedData == null)
			throw new ArgumentNullException(nameof(encryptedData));

		var buffer = new byte[encryptedData.Length];

		using var aes = Aes.Create();

		if (aes == null)
			throw new InvalidOperationException($"{nameof(aes)} == null");

		aes.Key = aesKey ?? throw new ArgumentNullException(nameof(aesKey));

		var iv = new byte[aes.IV.Length];
		var ciphertext = new byte[buffer.Length - iv.Length];

		Array.ConstrainedCopy(encryptedData, 0, iv, 0, iv.Length);
		Array.ConstrainedCopy(encryptedData, iv.Length, ciphertext, 0, ciphertext.Length);

		aes.IV = iv;

		using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
		using var resultStream = new MemoryStream();
		using (var aesStream = new CryptoStream(resultStream, decryptor, CryptoStreamMode.Write))
		using (var plainStream = new MemoryStream(ciphertext))
		{
			plainStream.CopyTo(aesStream);
		}

		return resultStream;
	}
}
