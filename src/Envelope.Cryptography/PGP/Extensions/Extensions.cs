using System.Text;

namespace Envelope.Cryptography.PGP;

internal static class Extensions
{
	public static Stream GetStream(this string s, Encoding? encoding)
	{
		var stream = new MemoryStream();
		var writer = encoding != null
			? new StreamWriter(stream, encoding)
			: new StreamWriter(stream);

		writer.Write(s);
		writer.Flush();
		stream.Seek(0, SeekOrigin.Begin);
		return stream;
	}

	public static async Task<Stream> GetStreamAsync(this string s, Encoding? encoding)
	{
		var stream = new MemoryStream();
		var writer = encoding != null
			? new StreamWriter(stream, encoding)
			: new StreamWriter(stream);

		await writer.WriteAsync(s);
		await writer.FlushAsync();
		stream.Seek(0, SeekOrigin.Begin);
		return stream;
	}

	public static string GetString(this Stream inputStream, Encoding? encoding)
	{
		var reader = encoding != null
			? new StreamReader(inputStream, encoding)
			: new StreamReader(inputStream);

		var output = reader.ReadToEnd();
		return output;
	}

	public static Task<string> GetStringAsync(this Stream inputStream, Encoding? encoding)
	{
		var reader = encoding != null
			? new StreamReader(inputStream, encoding)
			: new StreamReader(inputStream);

		return reader.ReadToEndAsync();
	}
}
