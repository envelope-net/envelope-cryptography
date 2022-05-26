using Envelope.Cryptography.PGP.Internal;
using Org.BouncyCastle.Bcpg;

namespace Envelope.Cryptography.PGP;

public interface IPGPOptionsBuilder<TBuilder, TObject>
	where TBuilder : IPGPOptionsBuilder<TBuilder, TObject>
	where TObject : IPGPOptions
{
	TBuilder Object(TObject options);

	TObject Build();

	TBuilder CompressionAlgorithm(CompressionAlgorithmTag compressionAlgorithm, bool force = false);

	TBuilder SymmetricKeyAlgorithm(SymmetricKeyAlgorithmTag symmetricKeyAlgorithm, bool force = false);

	TBuilder SignatureType(int signatureType, bool force = false);

	TBuilder PublicKeyAlgorithm(PublicKeyAlgorithmTag publicKeyAlgorithm, bool force = true);

	TBuilder FileType(PGPFileType fileType, bool force = true);

	TBuilder HashAlgorithm(HashAlgorithmTag hashAlgorithm, bool force = false);
}

public abstract class PGPOptionsBuilderBase<TBuilder, TObject> : IPGPOptionsBuilder<TBuilder, TObject>
	where TBuilder : PGPOptionsBuilderBase<TBuilder, TObject>
	where TObject : IPGPOptions
{
	protected readonly TBuilder _builder;
	protected TObject _options;

	protected PGPOptionsBuilderBase(TObject options)
	{
		_options = options;
		_builder = (TBuilder)this;
	}

	public virtual TBuilder Object(TObject options)
	{
		_options = options;
		return _builder;
	}

	public TObject Build()
		=> _options;

	public TBuilder CompressionAlgorithm(CompressionAlgorithmTag compressionAlgorithm, bool force = false)
	{
		if (force || _options.CompressionAlgorithm == default)
			_options.CompressionAlgorithm = compressionAlgorithm;

		return _builder;
	}

	public TBuilder SymmetricKeyAlgorithm(SymmetricKeyAlgorithmTag symmetricKeyAlgorithm, bool force = false)
	{
		if (force || _options.SymmetricKeyAlgorithm == default)
			_options.SymmetricKeyAlgorithm = symmetricKeyAlgorithm;

		return _builder;
	}

	public TBuilder SignatureType(int signatureType, bool force = false)
	{
		if (force || _options.PgpSignatureType == default)
			_options.PgpSignatureType = signatureType;

		return _builder;
	}

	public TBuilder PublicKeyAlgorithm(PublicKeyAlgorithmTag publicKeyAlgorithm, bool force = true)
	{
		if (force || _options.PublicKeyAlgorithm == default)
			_options.PublicKeyAlgorithm = publicKeyAlgorithm;

		return _builder;
	}

	public TBuilder FileType(PGPFileType fileType, bool force = true)
	{
		if (force || _options.FileType == default)
			_options.FileType = fileType;

		return _builder;
	}

	public TBuilder HashAlgorithm(HashAlgorithmTag hashAlgorithm, bool force = false)
	{
		if (force || _options.HashAlgorithm == default)
			_options.HashAlgorithm = hashAlgorithm;

		return _builder;
	}
}

public class PGPOptionsBuilder : PGPOptionsBuilderBase<PGPOptionsBuilder, IPGPOptions>
{
	public PGPOptionsBuilder()
		: base(new PGPOptions())
	{
	}

	public PGPOptionsBuilder(PGPOptions options)
		: base(options)
	{
	}

	public static implicit operator PGPOptions?(PGPOptionsBuilder builder)
	{
		if (builder == null)
			return null;

		return builder._options as PGPOptions;
	}

	public static implicit operator PGPOptionsBuilder?(PGPOptions options)
	{
		if (options == null)
			return null;

		return new PGPOptionsBuilder(options);
	}
}
