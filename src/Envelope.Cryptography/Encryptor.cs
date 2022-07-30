using System.Security.Cryptography;

namespace Envelope.Cryptography;

public class Encryptor
{
	/// <summary>
	/// 
	/// </summary>
	/// <param name="plainData"></param>
	/// <param name="aesKey">32 bytes length key</param>
	public static byte[] AESEncrypt(byte[] plainData, byte[] aesKey)
	{
		if (plainData == null)
			throw new ArgumentNullException(nameof(plainData));

		using var aes = Aes.Create();
		if (aes == null)
			throw new InvalidOperationException($"{nameof(aes)} == null");

		aes.Key = aesKey ?? throw new ArgumentNullException(nameof(aesKey));

		using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
		using var resultStream = new MemoryStream();
		using (var aesStream = new CryptoStream(resultStream, encryptor, CryptoStreamMode.Write))
		using (var plainStream = new MemoryStream(plainData))
		{
			plainStream.CopyTo(aesStream);
		}

		var result = resultStream.ToArray();
		var combined = new byte[aes.IV.Length + result.Length];
		Array.ConstrainedCopy(aes.IV, 0, combined, 0, aes.IV.Length);
		Array.ConstrainedCopy(result, 0, combined, aes.IV.Length, result.Length);

		return combined;
	}

	/// <summary>
	/// 
	/// </summary>
	/// <param name="plainStream"></param>
	/// <param name="aesKey">32 bytes length key</param>
	public static byte[] AESEncrypt(MemoryStream plainStream, byte[] aesKey)
	{
		if (plainStream == null)
			throw new ArgumentNullException(nameof(plainStream));

		if (plainStream.CanSeek)
			plainStream.Seek(0, SeekOrigin.Begin);

		using var aes = Aes.Create();
		if (aes == null)
			throw new InvalidOperationException($"{nameof(aes)} == null");

		aes.Key = aesKey ?? throw new ArgumentNullException(nameof(aesKey));

		using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
		using var resultStream = new MemoryStream();
		using (var aesStream = new CryptoStream(resultStream, encryptor, CryptoStreamMode.Write))
		{
			plainStream.CopyTo(aesStream);
		}

		var result = resultStream.ToArray();
		var combined = new byte[aes.IV.Length + result.Length];
		Array.ConstrainedCopy(aes.IV, 0, combined, 0, aes.IV.Length);
		Array.ConstrainedCopy(result, 0, combined, aes.IV.Length, result.Length);

		return combined;
	}
}
