using Envelope.Exceptions;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.Text;

namespace Envelope.Cryptography.PGP;

public partial class PGPProvider : IPGPEncrypt, IPGPEncryptAndSign, IPGPSign, IPGPClearSign, IPGPDecrypt, IPGPDecryptAndVerify, IPGPGetRecipients, IPGPGenerateKey
{
	private const int BufferSize = 0x10000;
	public const string DefaultFileName = "name";

	private static readonly byte[] LineSeparator = Encoding.ASCII.GetBytes(Environment.NewLine);

	private readonly IPGPOptions _options;

	public PGPProvider()
	{
		var builder = new PGPOptionsBuilder();
		_options = builder.Build();
	}

	public PGPProvider(IPGPOptions options)
	{
		_options = options ?? throw new ArgumentNullException(nameof(options));
		var error = _options.Validate()?.ToString();
		if (!string.IsNullOrWhiteSpace(error))
			throw new ConfigurationException(error);
	}

	public PGPProvider(Action<PGPOptionsBuilder> configure)
	{
		var builder = new PGPOptionsBuilder();
		configure?.Invoke(builder);
		_options = builder.Build();

		var error = _options.Validate()?.ToString();
		if (!string.IsNullOrWhiteSpace(error))
			throw new ConfigurationException(error);
	}

	private char FileTypeToChar()
	{
		if (_options.FileType == PGPFileType.UTF8)
			return PgpLiteralData.Utf8;
		else if (_options.FileType == PGPFileType.Text)
			return PgpLiteralData.Text;
		else
			return PgpLiteralData.Binary;

	}

	private static bool IsWhiteSpace(byte b)
	{
		return IsLineEnding(b) || b == '\t' || b == ' ';
	}

	private static int GetLengthWithoutSeparatorOrTrailingWhitespace(byte[] line)
	{
		int end = line.Length - 1;

		while (end >= 0 && IsWhiteSpace(line[end]))
			end--;

		return end + 1;
	}
}
